//! EIP-7928 on the pipeline/backfill path: `run_wrapped_block` rebuilds the block access list
//! during re-execution, so its BAL index must advance exactly as upstream
//! `BasicBlockExecutor::execute_one` advances it. This test runs a multi-transaction Amsterdam
//! block through upstream first to get the reference hash, then through `run_wrapped_block`, and
//! checks that the rebuilt list matches that hash and is emitted as RLP.

use std::{path::PathBuf, sync::Arc};

use alloy_consensus::{
    constants::EMPTY_WITHDRAWALS, proofs::calculate_transaction_root, Header, SignableTransaction,
    TxEip1559, EMPTY_OMMER_ROOT_HASH,
};
use alloy_eips::eip4895::Withdrawals;
use alloy_primitives::{address, hex, keccak256, Address, Bytes, TxKind, B256, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use reth_chainspec::ChainSpec;
use reth_ethereum_primitives::{Block, BlockBody, EthPrimitives, TransactionSigned};
use reth_evm::execute::{BasicBlockExecutor, Executor};
use reth_evm_ethereum::EthEvmConfig;
use reth_firehose::{run_wrapped_block, take_traced_block_access_list, FirehoseBlockTracer, NoPostTxExtras, NoPreTxAdjust};
use reth_firehose_tests::prestate::{parse_fire_block_for, seed_cache_db, Prestate};
use reth_primitives_traits::{Block as _, RecoveredBlock};
use reth_revm::State;
use revm::database::{CacheDB, EmptyDB};

const RECIPIENT: Address = address!("0x000000000000000000000000000000000000beef");

/// Runtime code: `SSTORE(1, 0x2a)`.
const RUNTIME: [u8; 6] = hex!("602a60015500");

#[test]
fn pipeline_rebuilds_bal_of_a_block_with_transactions() {
    let signer = PrivateKeySigner::from_bytes(&B256::repeat_byte(0x42)).unwrap();
    let sender = signer.address();

    // Amsterdam genesis from the prestate fixture, with the sender funded.
    let case = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/cases/amsterdam_block_access_list/prestate.json");
    let mut prestate: Prestate = serde_json::from_slice(&std::fs::read(case).unwrap()).unwrap();
    prestate.genesis.alloc.insert(
        sender,
        alloy_genesis::GenesisAccount::default().with_balance(U256::from(10u128.pow(20))),
    );
    let chain_spec = Arc::new(ChainSpec::from(prestate.genesis.clone()));

    // Init code: `SSTORE(0, 7)`, then return `RUNTIME`.
    let mut initcode = hex!("6007600055" "6006601160003960066000f3").to_vec();
    initcode.extend_from_slice(&RUNTIME);
    let created = sender.create(1);

    let txs = [
        (TxKind::Call(RECIPIENT), U256::from(10u128.pow(18)), Bytes::new()),
        (TxKind::Create, U256::from(5), Bytes::from(initcode)),
        (TxKind::Call(created), U256::ZERO, Bytes::new()),
    ];
    let transactions: Vec<TransactionSigned> = txs
        .into_iter()
        .enumerate()
        .map(|(nonce, (to, value, input))| {
            let tx = TxEip1559 {
                chain_id: prestate.genesis.config.chain_id,
                nonce: nonce as u64,
                gas_limit: 1_000_000,
                max_fee_per_gas: 1_000_000_000,
                max_priority_fee_per_gas: 1,
                to,
                value,
                input,
                ..Default::default()
            };
            let signature = signer.sign_hash_sync(&tx.signature_hash()).unwrap();
            TransactionSigned::new_unhashed(tx.into(), signature)
        })
        .collect();

    // Upstream executor, with a placeholder hash that only arms its BAL builder.
    let placeholder = block(&prestate, &transactions, B256::repeat_byte(0x11));
    let mut upstream =
        BasicBlockExecutor::new(EthEvmConfig::new(chain_spec.clone()), state(&prestate));
    let upstream_result = upstream.execute_one(&placeholder).expect("upstream executes the block");
    assert!(
        upstream_result.receipts.iter().all(|r| r.success),
        "every transaction must succeed, or the block tests less than it claims"
    );
    let expected = alloy_eip7928::compute_block_access_list_hash(
        &upstream.take_bal().expect("upstream builds a BAL"),
    );

    // The same block, now declaring the real hash, through the Firehose pipeline path.
    let block = block(&prestate, &transactions, expected);
    let (mut tracer, buffer) = firehose_tracer::Tracer::with_buffer(
        firehose_tracer::config::Config::default(),
        firehose_tracer::config::ChainConfig {
            chain_id: prestate.genesis.config.chain_id,
            shanghai_time: Some(0),
            cancun_time: Some(0),
            prague_time: Some(0),
            verkle_time: None,
        },
        "reth-firehose-tests",
        env!("CARGO_PKG_VERSION"),
    );
    let mut guard =
        FirehoseBlockTracer::start_local::<EthPrimitives>(&mut tracer, block.sealed_block(), None);
    let mut db = state(&prestate);
    run_wrapped_block(
        &EthEvmConfig::new(chain_spec),
        &mut db,
        &block,
        &mut guard,
        NoPreTxAdjust,
        NoPostTxExtras,
    )
    .and_then(|result| {
        take_traced_block_access_list(&mut db, &block, &mut guard)?;
        Ok(result)
    })
    .expect("the rebuilt BAL must match upstream's hash");
    guard.mark_verified();

    let emitted = parse_fire_block_for(&buffer.get_bytes(), block.header().number).unwrap();
    let header = emitted.header.expect("emitted block has a header");
    assert_eq!(header.block_access_list_hash.as_deref(), Some(expected.as_slice()));
    let rlp = header.block_access_list_rlp.expect("BAL RLP is emitted");
    assert_eq!(keccak256(&rlp), expected, "the emitted RLP must hash to the header's BAL hash");
    assert_eq!(emitted.transaction_traces.len(), 3);
}

fn state(prestate: &Prestate) -> State<CacheDB<EmptyDB>> {
    let mut db = CacheDB::new(EmptyDB::default());
    seed_cache_db(&mut db, &prestate.genesis).unwrap();
    State::builder().with_database(db).with_bundle_update().build()
}

fn block(
    prestate: &Prestate,
    transactions: &[TransactionSigned],
    bal_hash: B256,
) -> RecoveredBlock<Block> {
    let ctx = &prestate.context;
    let header = Header {
        parent_hash: B256::ZERO,
        ommers_hash: EMPTY_OMMER_ROOT_HASH,
        beneficiary: ctx.miner,
        transactions_root: calculate_transaction_root(transactions),
        withdrawals_root: Some(EMPTY_WITHDRAWALS),
        number: ctx.number,
        timestamp: ctx.timestamp,
        gas_limit: ctx.gas_limit,
        base_fee_per_gas: ctx.base_fee_per_gas.map(|v| v as u64),
        parent_beacon_block_root: Some(B256::ZERO),
        blob_gas_used: Some(0),
        excess_blob_gas: Some(0),
        slot_number: Some(1),
        block_access_list_hash: Some(bal_hash),
        ..Default::default()
    };
    Block {
        header,
        body: BlockBody {
            transactions: transactions.to_vec(),
            ommers: vec![],
            withdrawals: Some(Withdrawals::default()),
        },
    }
    .try_into_recovered()
    .unwrap()
}
