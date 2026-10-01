//! Per-reason counter for transactions that RPC clients submit and the node rejects.
//!
//! The transaction pool counts rejections too, but it mixes RPC submissions with p2p gossip and
//! puts most stateful rejections into one counter. This counter covers only RPC submissions and
//! gives each rejection one reason from a fixed set, so the label cardinality stays bounded.

use reth_primitives_traits::transaction::error::InvalidTransactionError;
use reth_transaction_pool::error::{InvalidPoolTransactionError, PoolError, PoolErrorKind};

/// Name of the counter. The node's Prometheus recorder adds the `reth_` prefix, so operators see
/// `reth_rpc_eth_send_raw_rejected_total`.
pub const SEND_RAW_REJECTED_TOTAL: &str = "rpc.eth.send_raw_rejected_total";

/// Why the node rejected a transaction that an RPC client submitted.
///
/// Each variant is one value of the `reason` label of [`SEND_RAW_REJECTED_TOTAL`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SendRawRejectReason {
    /// The raw bytes do not decode to a transaction, or the signer does not recover.
    Decode,
    /// The pool already has this transaction.
    AlreadyKnown,
    /// The transaction replaces a pooled one but does not raise the fee enough.
    ReplacementUnderpriced,
    /// The fee is below the pool's or the protocol's minimum.
    Underpriced,
    /// The pool has no space for the transaction, or for more transactions from its sender.
    PoolFull,
    /// The sender has a pooled transaction of a type that excludes this one (blob vs non-blob).
    ConflictingType,
    /// The nonce does not follow the sender's state nonce.
    NonceTooLow,
    /// The sender cannot pay for the transaction.
    InsufficientFunds,
    /// The maximum fee is above the configured `--rpc.txfeecap`.
    FeeCap,
    /// The gas limit is below the intrinsic gas.
    IntrinsicGas,
    /// The gas limit is above the block gas limit or the per-transaction maximum.
    GasLimit,
    /// Any other rejection.
    Other,
}

impl SendRawRejectReason {
    /// Every reason, in label order.
    pub const ALL: [Self; 12] = [
        Self::Decode,
        Self::AlreadyKnown,
        Self::ReplacementUnderpriced,
        Self::Underpriced,
        Self::PoolFull,
        Self::ConflictingType,
        Self::NonceTooLow,
        Self::InsufficientFunds,
        Self::FeeCap,
        Self::IntrinsicGas,
        Self::GasLimit,
        Self::Other,
    ];

    /// Returns the value of the `reason` label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Decode => "decode",
            Self::AlreadyKnown => "already_known",
            Self::ReplacementUnderpriced => "replacement_underpriced",
            Self::Underpriced => "underpriced",
            Self::PoolFull => "pool_full",
            Self::ConflictingType => "conflicting_type",
            Self::NonceTooLow => "nonce_too_low",
            Self::InsufficientFunds => "insufficient_funds",
            Self::FeeCap => "fee_cap",
            Self::IntrinsicGas => "intrinsic_gas",
            Self::GasLimit => "gas_limit",
            Self::Other => "other",
        }
    }

    /// Returns the reason for a pool rejection.
    ///
    /// The matches have no wildcard arm, so a new error variant does not compile until somebody
    /// picks its reason.
    pub const fn from_pool_error(err: &PoolError) -> Self {
        match &err.kind {
            PoolErrorKind::AlreadyImported => Self::AlreadyKnown,
            PoolErrorKind::ReplacementUnderpriced => Self::ReplacementUnderpriced,
            PoolErrorKind::FeeCapBelowMinimumProtocolFeeCap(_) => Self::Underpriced,
            PoolErrorKind::SpammerExceededCapacity(_) | PoolErrorKind::DiscardedOnInsert => {
                Self::PoolFull
            }
            PoolErrorKind::ExistingConflictingTransactionType(..) => Self::ConflictingType,
            PoolErrorKind::InvalidTransaction(err) => Self::from_invalid_pool_transaction(err),
            PoolErrorKind::Other(_) => Self::Other,
        }
    }

    /// Returns the reason for a transaction that the pool validator rejected.
    pub const fn from_invalid_pool_transaction(err: &InvalidPoolTransactionError) -> Self {
        match err {
            InvalidPoolTransactionError::Consensus(err) => Self::from_invalid_transaction(err),
            InvalidPoolTransactionError::Overdraft { .. } => Self::InsufficientFunds,
            InvalidPoolTransactionError::ExceedsFeeCap { .. } => Self::FeeCap,
            InvalidPoolTransactionError::IntrinsicGasTooLow => Self::IntrinsicGas,
            InvalidPoolTransactionError::ExceedsGasLimit(..) |
            InvalidPoolTransactionError::MaxTxGasLimitExceeded(..) => Self::GasLimit,
            InvalidPoolTransactionError::Underpriced |
            InvalidPoolTransactionError::PriorityFeeBelowMinimum { .. } => Self::Underpriced,
            InvalidPoolTransactionError::ExceedsMaxInitCodeSize(..) |
            InvalidPoolTransactionError::OversizedData { .. } |
            InvalidPoolTransactionError::Eip2681 |
            InvalidPoolTransactionError::Eip4844(_) |
            InvalidPoolTransactionError::Eip7702(_) |
            InvalidPoolTransactionError::Other(_) => Self::Other,
        }
    }

    /// Returns the reason for a consensus rule that the transaction breaks.
    pub const fn from_invalid_transaction(err: &InvalidTransactionError) -> Self {
        match err {
            // The pool queues a nonce above the state nonce, so this error means a stale nonce.
            InvalidTransactionError::NonceNotConsistent { .. } => Self::NonceTooLow,
            InvalidTransactionError::InsufficientFunds(_) => Self::InsufficientFunds,
            InvalidTransactionError::GasTooLow => Self::IntrinsicGas,
            InvalidTransactionError::GasTooHigh | InvalidTransactionError::GasLimitTooHigh => {
                Self::GasLimit
            }
            InvalidTransactionError::FeeCapTooLow => Self::Underpriced,
            InvalidTransactionError::OldLegacyChainId |
            InvalidTransactionError::ChainIdMismatch |
            InvalidTransactionError::Eip2930Disabled |
            InvalidTransactionError::Eip1559Disabled |
            InvalidTransactionError::Eip4844Disabled |
            InvalidTransactionError::Eip7702Disabled |
            InvalidTransactionError::TxTypeNotSupported |
            InvalidTransactionError::GasUintOverflow |
            InvalidTransactionError::TipAboveFeeCap |
            InvalidTransactionError::SignerAccountHasBytecode => Self::Other,
        }
    }

    /// Increments [`SEND_RAW_REJECTED_TOTAL`] for this reason.
    pub fn record(self) {
        metrics::counter!(SEND_RAW_REJECTED_TOTAL, "reason" => self.as_str()).increment(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, TxHash, U256};
    use reth_primitives_traits::GotExpected;
    use std::collections::HashSet;
    use SendRawRejectReason as R;

    fn pool_error(kind: PoolErrorKind) -> PoolError {
        PoolError::new(TxHash::ZERO, kind)
    }

    fn invalid(err: InvalidPoolTransactionError) -> PoolError {
        pool_error(PoolErrorKind::InvalidTransaction(err))
    }

    #[test]
    fn labels_are_unique_and_bounded() {
        let labels: HashSet<_> =
            SendRawRejectReason::ALL.iter().map(|reason| reason.as_str()).collect();
        assert_eq!(labels.len(), SendRawRejectReason::ALL.len());
        assert!(labels.len() <= 14);
    }

    #[test]
    fn maps_pool_errors() {
        let cases = [
            (pool_error(PoolErrorKind::AlreadyImported), R::AlreadyKnown),
            (pool_error(PoolErrorKind::ReplacementUnderpriced), R::ReplacementUnderpriced),
            (pool_error(PoolErrorKind::FeeCapBelowMinimumProtocolFeeCap(1)), R::Underpriced),
            (pool_error(PoolErrorKind::SpammerExceededCapacity(Address::ZERO)), R::PoolFull),
            (pool_error(PoolErrorKind::DiscardedOnInsert), R::PoolFull),
            (
                pool_error(PoolErrorKind::ExistingConflictingTransactionType(Address::ZERO, 3)),
                R::ConflictingType,
            ),
            (pool_error(PoolErrorKind::Other("db".into())), R::Other),
            (
                invalid(InvalidTransactionError::NonceNotConsistent { tx: 0, state: 1 }.into()),
                R::NonceTooLow,
            ),
            (
                invalid(
                    InvalidTransactionError::InsufficientFunds(
                        GotExpected { got: U256::ZERO, expected: U256::from(1) }.into(),
                    )
                    .into(),
                ),
                R::InsufficientFunds,
            ),
            (
                invalid(InvalidPoolTransactionError::Overdraft {
                    cost: U256::from(1),
                    balance: U256::ZERO,
                }),
                R::InsufficientFunds,
            ),
            (
                invalid(InvalidPoolTransactionError::ExceedsFeeCap {
                    max_tx_fee_wei: 2,
                    tx_fee_cap_wei: 1,
                }),
                R::FeeCap,
            ),
            (invalid(InvalidPoolTransactionError::IntrinsicGasTooLow), R::IntrinsicGas),
            (invalid(InvalidTransactionError::GasTooLow.into()), R::IntrinsicGas),
            (invalid(InvalidPoolTransactionError::ExceedsGasLimit(2, 1)), R::GasLimit),
            (invalid(InvalidPoolTransactionError::MaxTxGasLimitExceeded(2, 1)), R::GasLimit),
            (invalid(InvalidTransactionError::GasLimitTooHigh.into()), R::GasLimit),
            (invalid(InvalidPoolTransactionError::Underpriced), R::Underpriced),
            (invalid(InvalidTransactionError::FeeCapTooLow.into()), R::Underpriced),
            (
                invalid(InvalidPoolTransactionError::PriorityFeeBelowMinimum {
                    minimum_priority_fee: 1,
                }),
                R::Underpriced,
            ),
            (invalid(InvalidTransactionError::ChainIdMismatch.into()), R::Other),
            (invalid(InvalidPoolTransactionError::Eip2681), R::Other),
        ];

        for (err, expected) in cases {
            assert_eq!(SendRawRejectReason::from_pool_error(&err), expected, "{err:?}");
        }
    }
}
