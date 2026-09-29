use crate::spec::DepositContract;
use alloy_eips::eip6110::MAINNET_DEPOSIT_CONTRACT_ADDRESS;
use alloy_primitives::b256;

/// Gas per transaction not creating a contract.
pub const MIN_TRANSACTION_GAS: u64 = 21_000u64;

/// Mainnet prune delete limit.
pub const MAINNET_PRUNE_DELETE_LIMIT: usize = 20000;

/// Deposit contract address: `0x00000000219ab540356cbb839cbe05303d7705fa`
pub(crate) const MAINNET_DEPOSIT_CONTRACT: DepositContract = DepositContract::new(
    MAINNET_DEPOSIT_CONTRACT_ADDRESS,
    11052984,
    b256!("0x649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c5"),
);

/// `PulseChain` mainnet chain ID.
pub const PULSECHAIN_MAINNET_CHAIN_ID: u64 = 369;

/// `PulseChain` testnet v4 chain ID.
pub const PULSECHAIN_TESTNET_V4_CHAIN_ID: u64 = 943;

/// Returns whether `chain_id` is a `PulseChain` network.
pub const fn is_pulsechain_chain_id(chain_id: u64) -> bool {
    matches!(chain_id, PULSECHAIN_MAINNET_CHAIN_ID | PULSECHAIN_TESTNET_V4_CHAIN_ID)
}
