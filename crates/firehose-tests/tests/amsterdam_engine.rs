//! Regression test: the Firehose-traced engine path accepts Amsterdam blocks.
//!
//! While the tracer is installed, the engine validates every payload on the traced path. On an
//! Amsterdam block that path must build the block access list, so post-execution validation can
//! check it against the header's `block_access_list_hash`. The check passes only when the traced
//! path builds the same access list as the block builder did.
//!
//! Each block below covers one case where the traced executor's extra state reads or balance
//! events could make its access list differ from the builder's.
//!
//! It lives in its own integration-test binary because it installs the process-wide tracer.

use std::sync::{Arc, Mutex};

use alloy_eips::eip4895::Withdrawal;
use alloy_primitives::{address, hex, Address, Bytes, TxKind, U256};
use alloy_rpc_types_engine::PayloadStatusEnum;
use alloy_rpc_types_eth::{TransactionInput, TransactionRequest};
use base64::{engine::general_purpose, Engine as _};
use firehose_tracer::pb::sf::ethereum::r#type::v2::Block as FirehoseBlock;
use prost::Message as _;
use reth_chainspec::EthereumHardfork;
use reth_e2e_test_utils::{
    eth_payload_attributes, test_chain_spec, transaction::TransactionTestContext, wallet::Wallet,
    E2ETestSetupExt, NodeHelperType,
};
use reth_firehose::init_tracer;
use reth_node_ethereum::EthereumNode;

/// Recipient of the withdrawal block's withdrawals.
const WITHDRAWAL_RECIPIENT: Address = address!("0x00000000000000000000000000000000000000aa");

#[tokio::test(flavor = "multi_thread")]
async fn traced_engine_path_accepts_amsterdam_blocks() -> eyre::Result<()> {
    let (tracer, buffer) = firehose_tracer::Tracer::with_buffer(
        firehose_tracer::config::Config::default(),
        // firehose-tracer 5.4.4's ChainConfig has no Amsterdam field; these are all it takes.
        firehose_tracer::config::ChainConfig {
            chain_id: 1,
            shanghai_time: Some(0),
            cancun_time: Some(0),
            prague_time: Some(0),
            verkle_time: None,
        },
        "reth-firehose-tests",
        env!("CARGO_PKG_VERSION"),
    );
    init_tracer(tracer);

    // The builder's next payload takes its withdrawals from here.
    let withdrawals = Arc::new(Mutex::new(Vec::<Withdrawal>::new()));
    let chain_spec = test_chain_spec(EthereumHardfork::Amsterdam);
    let generator_withdrawals = Arc::clone(&withdrawals);
    let (mut nodes, wallet) = EthereumNode::test_setup_for(EthereumHardfork::Amsterdam)
        .with_num_nodes(2)
        .with_attributes_generator(move |timestamp| {
            let mut attributes = eth_payload_attributes(&*chain_spec, timestamp);
            attributes.withdrawals = Some(generator_withdrawals.lock().unwrap().clone());
            attributes
        })
        .build()
        .await?;
    let validator = nodes.pop().unwrap();
    let builder = nodes.pop().unwrap();
    let mut chain = Chain { builder, validator, buffer, withdrawals, wallet, nonce: 0 };

    // A plain transfer.
    let tx = chain.tx(TxKind::Call(Address::with_last_byte(1)), U256::from(1), Bytes::new(), 1);
    chain.block("transfer", vec![tx], Vec::new()).await?;

    // A zero priority fee leaves the coinbase untouched.
    let tx = chain.tx(TxKind::Call(Address::with_last_byte(1)), U256::from(1), Bytes::new(), 0);
    chain.block("zero priority fee", vec![tx], Vec::new()).await?;

    // Nonzero withdrawals, two to one address, and a zero-amount one.
    let withdrawal =
        |index, address, amount| Withdrawal { index, validator_index: index, address, amount };
    let block_withdrawals = vec![
        withdrawal(0, WITHDRAWAL_RECIPIENT, 1_000),
        withdrawal(1, WITHDRAWAL_RECIPIENT, 2_000),
        withdrawal(2, Address::with_last_byte(0xbb), 0),
        withdrawal(3, Address::with_last_byte(0xcc), 3_000),
    ];
    chain.block("withdrawals", Vec::new(), block_withdrawals).await?;

    // A reverted transaction (init code `REVERT(0, 0)`) and one that runs out of gas (init code
    // loops forever).
    let reverted = chain.tx(TxKind::Create, U256::ZERO, hex!("60006000fd").into(), 1);
    let out_of_gas = chain.tx(TxKind::Create, U256::ZERO, hex!("5b600056").into(), 1);
    chain.block("reverted and out of gas", vec![reverted, out_of_gas], Vec::new()).await?;

    // A CREATE that deploys the one-byte runtime code 0xff.
    let create = chain.tx(TxKind::Create, U256::ZERO, hex!("60ff60005360016000f3").into(), 1);
    chain.block("create", vec![create], Vec::new()).await?;

    // A block with no transactions.
    chain.block("empty", Vec::new(), Vec::new()).await?;

    // CREATE and SELFDESTRUCT in one transaction: the init code sends the endowment to 0x0.
    let tx = chain.tx(TxKind::Create, U256::from(7), hex!("6000ff").into(), 1);
    chain.block("create and selfdestruct", vec![tx], Vec::new()).await?;

    Ok(())
}

/// Two nodes: one builds each block, the other validates it on the traced path.
struct Chain {
    builder: NodeHelperType<EthereumNode>,
    validator: NodeHelperType<EthereumNode>,
    buffer: firehose_tracer::InMemoryBuffer,
    withdrawals: Arc<Mutex<Vec<Withdrawal>>>,
    wallet: Wallet,
    nonce: u64,
}

impl Chain {
    /// Signs the wallet's next transaction.
    fn tx(
        &mut self,
        to: TxKind,
        value: U256,
        input: Bytes,
        priority_fee: u128,
    ) -> TransactionRequest {
        let request = TransactionRequest {
            nonce: Some(self.nonce),
            chain_id: Some(1),
            gas: Some(100_000),
            max_fee_per_gas: Some(1_000_000_000_000),
            max_priority_fee_per_gas: Some(priority_fee),
            to: Some(to),
            value: Some(value),
            input: TransactionInput::new(input),
            ..Default::default()
        };
        self.nonce += 1;
        request
    }

    /// Builds a block with `txs` and `withdrawals`, then checks that the validator accepts it on
    /// the traced path and emits it once with its block access list hash.
    async fn block(
        &mut self,
        case: &str,
        txs: Vec<TransactionRequest>,
        withdrawals: Vec<Withdrawal>,
    ) -> eyre::Result<()> {
        let tx_count = txs.len();
        for request in txs {
            let raw =
                TransactionTestContext::sign_tx_bytes(self.wallet.inner.clone(), request).await;
            self.builder.rpc.inject_tx(raw).await?;
        }
        *self.withdrawals.lock().unwrap() = withdrawals;

        let payload = self.builder.new_payload().await?;
        let block = payload.block().clone();
        let hash = block.hash();
        assert!(block.header().block_access_list_hash.is_some(), "{case}: not an Amsterdam block");
        assert_eq!(block.body().transactions.len(), tx_count, "{case}: builder dropped a tx");

        let before = fire_blocks(&self.buffer.get_bytes()).len();
        let status = self
            .validator
            .inner
            .add_ons_handle
            .beacon_engine_handle
            .new_payload(payload.clone().into())
            .await?;
        assert_eq!(status.status, PayloadStatusEnum::Valid, "{case}: traced path rejected it");
        let emitted = fire_blocks(&self.buffer.get_bytes());
        assert_eq!(emitted.len(), before + 1, "{case}: traced path did not emit the block once");
        let emitted = emitted.last().unwrap();
        assert_eq!(emitted.hash, hash.to_vec(), "{case}: emitted another block");
        let header = emitted.header.as_ref().expect("emitted block has a header");
        assert!(header.block_access_list_hash.is_some(), "{case}: emitted no BAL hash");

        self.validator.update_forkchoice(hash, hash).await?;
        self.builder.submit_payload(payload).await?;
        self.builder.update_forkchoice(hash, hash).await?;
        Ok(())
    }
}

/// Decodes every `FIRE BLOCK` line in the tracer output.
fn fire_blocks(output: &[u8]) -> Vec<FirehoseBlock> {
    String::from_utf8_lossy(output)
        .lines()
        .filter(|line| line.starts_with("FIRE BLOCK "))
        .map(|line| {
            let payload = line.rsplit(' ').next().expect("FIRE BLOCK line has no payload");
            let bytes = general_purpose::STANDARD.decode(payload).expect("base64 payload");
            FirehoseBlock::decode(bytes.as_slice()).expect("protobuf block")
        })
        .collect()
}
