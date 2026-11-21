//! The transaction pool's chain ID check on `PulseChain`.
//!
//! `PulseChain` replayed Ethereum's history, so a transaction signed for chain
//! ID 1 is also valid on 369 and 943. The pool must accept it there, and only
//! there.

use alloy_primitives::Address;
use reth_chainspec::{ChainSpec, MAINNET, SEPOLIA};
use reth_evm_ethereum::EthEvmConfig;
use reth_primitives_traits::{transaction::error::InvalidTransactionError, SignedTransaction};
use reth_provider::test_utils::MockEthProvider;
use reth_pulsechain_forks::chainspec::{PULSECHAIN, PULSECHAIN_TESTNET_V4};
use reth_transaction_pool::{
    blobstore::InMemoryBlobStore, error::InvalidPoolTransactionError,
    test_utils::TransactionBuilder, validate::EthTransactionValidatorBuilder, EthPooledTransaction,
    PoolTransaction, TransactionOrigin,
};
use std::sync::Arc;

/// Validates a transaction signed for `tx_chain_id` on a node running `spec`.
fn validate(spec: &Arc<ChainSpec>, tx_chain_id: u64) -> Result<(), InvalidPoolTransactionError> {
    let provider = MockEthProvider::default().with_chain_spec(spec.clone()).with_genesis_block();
    let validator = EthTransactionValidatorBuilder::new(provider, EthEvmConfig::new(spec.clone()))
        .set_block_gas_limit(30_000_000)
        .build(InMemoryBlobStore::default());
    let transaction = EthPooledTransaction::try_from_consensus(
        TransactionBuilder::default()
            .chain_id(tx_chain_id)
            .gas_limit(21_000)
            .to(Address::ZERO)
            .into_eip1559()
            .try_into_recovered()
            .unwrap(),
    )
    .unwrap();
    validator.validate_stateless(TransactionOrigin::External, &transaction).map(|_| ())
}

fn is_chain_id_mismatch(result: Result<(), InvalidPoolTransactionError>) -> bool {
    matches!(
        result,
        Err(InvalidPoolTransactionError::Consensus(InvalidTransactionError::ChainIdMismatch))
    )
}

/// 369 and 943 accept their own chain ID and Ethereum's, and nothing else.
#[test]
fn pulsechain_accepts_its_own_and_ethereum_chain_id() {
    for spec in [&*PULSECHAIN, &*PULSECHAIN_TESTNET_V4] {
        let own = spec.chain.id();
        validate(spec, own).unwrap();
        validate(spec, 1).unwrap();
        assert!(is_chain_id_mismatch(validate(spec, 2)), "chain {own}: chain ID 2");
        let other = if own == 369 { 943 } else { 369 };
        assert!(is_chain_id_mismatch(validate(spec, other)), "chain {own}: chain ID {other}");
    }
}

/// Other chains keep the stock check: chain ID 1 is foreign on Sepolia.
#[test]
fn other_chains_reject_ethereum_chain_id() {
    validate(&MAINNET, 1).unwrap();
    assert!(is_chain_id_mismatch(validate(&SEPOLIA, 1)));
}
