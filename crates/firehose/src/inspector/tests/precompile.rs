//! State changes a native precompile writes directly on the journal, with no SSTORE or LOG
//! opcode in between, and the value transfer of a precompile call that fails.

use super::support::*;
use crate::inspector::*;
use alloy_primitives::LogData;
use evm2::{
    interpreter::GasTracker,
    precompile::PrecompileOutput,
    precompiles::{Precompile, PrecompileId, PrecompileResult},
    BaseEvmTypes, Precompiles, SpecId,
};
use firehose_tracer::pb;
use reth_evm_ethereum::{EvmFactory, RethEvmFactory};

/// Slot and value [`journal_writer`] stores, and the topic and data of the log it emits.
const STORAGE_KEY: u64 = 7;
const STORAGE_VALUE: u64 = 42;
const LOG_TOPIC: B256 = B256::repeat_byte(0xcc);
const LOG_DATA: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];

/// The bn254 `ecAdd` precompile, which rejects a point that is not on the curve.
const EC_ADD: Address = Address::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6]);

/// Contract that calls [`REVERTER`] and then [`PRECOMPILE`].
const CALLER: Address = Address::repeat_byte(0xc1);

/// Contract that emits a `LOG0` and then reverts.
const REVERTER: Address = Address::repeat_byte(0x5e);

/// The node's EVM factory, with [`journal_writer`] installed at [`PRECOMPILE`].
#[derive(Debug, Clone, Default)]
struct JournalWriterFactory(RethEvmFactory);

impl EvmFactory for JournalWriterFactory {
    type Types = BaseEvmTypes;
    type SpecId = SpecId;

    fn spec_id(&self, spec: SpecId) -> SpecId {
        self.0.spec_id(spec)
    }

    fn tx_registry(
        &self,
        spec: SpecId,
    ) -> evm2::registry::TxRegistry<BaseEvmTypes, evm2::TxResult<BaseEvmTypes>> {
        self.0.tx_registry(spec)
    }

    fn precompiles(&self, spec: SpecId) -> Precompiles<BaseEvmTypes> {
        let mut precompiles = self.0.precompiles(spec);
        precompiles.as_map_mut().insert(Precompile::new(
            PRECOMPILE,
            PrecompileId::custom("journal-writer"),
            journal_writer,
        ));
        precompiles
    }
}

/// A native precompile in the shape of a B-20 transfer: it writes one storage slot, then emits
/// one log, both straight on the journal.
fn journal_writer(
    evm: &mut Evm<'_, BaseEvmTypes>,
    _message: &evm2::interpreter::Message<BaseEvmTypes>,
    _gas: &mut GasTracker,
) -> PrecompileResult {
    evm.state_mut()
        .storage_slot(&PRECOMPILE, U256::from(STORAGE_KEY))?
        .set(U256::from(STORAGE_VALUE));
    evm.log(AlloyLog {
        address: PRECOMPILE,
        data: LogData::new_unchecked(vec![LOG_TOPIC], Bytes::from_static(&LOG_DATA)),
    });
    Ok(PrecompileOutput::new(Bytes::new()))
}

/// Runs `txs` with [`journal_writer`] installed at [`PRECOMPILE`].
fn drive_with_journal_writer(
    accounts: &[(Address, AccountInfo)],
    txs: &[DriveTx],
) -> pb::sf::ethereum::r#type::v2::Block {
    BlockDriver::new(SpecId::PRAGUE, accounts)
        .with_evm_factory(JournalWriterFactory::default())
        .run(txs)
}

/// A native precompile writes one storage slot and emits one log directly on the journal
/// (no SSTORE/LOG opcode). Both must attach to the precompile's call frame: the log so the
/// call-log count matches the receipt (otherwise the tracer panics), and the storage change so
/// it is not silently dropped.
#[test]
fn precompile_journal_storage_and_logs_are_captured() {
    let block = drive_with_journal_writer(
        &[(SENDER, balance_account(1_000_000)), (PRECOMPILE, AccountInfo::default())],
        &[DriveTx::call(PRECOMPILE, 0)],
    );

    let trx = block.transaction_traces.first().expect("one transaction");
    let call = trx.calls.first().expect("one call");

    assert_eq!(call.logs.len(), 1, "precompile log must be attached to the call");
    assert_eq!(call.logs[0].address, PRECOMPILE.to_vec());
    assert_eq!(call.logs[0].block_index, 0);

    assert_eq!(
        call.storage_changes.len(),
        1,
        "precompile storage write must be attached to the call"
    );
    let change = &call.storage_changes[0];
    assert_eq!(change.address, PRECOMPILE.to_vec());
    assert_eq!(change.key, B256::from(U256::from(STORAGE_KEY)).to_vec());
    assert_eq!(change.new_value, B256::from(U256::from(STORAGE_VALUE)).to_vec());
    assert_eq!(change.old_value, B256::ZERO.to_vec());
}

/// Value sent to a precompile that then fails: evm2 rolls the transfer back with the frame,
/// before any hook sees it, and Geth still reports the debit and the credit, so must we. Here
/// the precompile rejects its input; [`super::gas_boundary`] covers one starved of gas.
#[test]
fn reverted_precompile_value_transfer_emits_balance_changes() {
    // (1, 1) is not on the curve, so `ecAdd` fails whatever the second point is.
    let mut input = [0u8; 128];
    input[31] = 1;
    input[63] = 1;

    // The precompile already holds a balance, as on a live chain, so the transfer does not
    // create an account.
    let accounts = [(SENDER, balance_account(1_000_000)), (EC_ADD, balance_account(500))];

    for spec in [SpecId::PRAGUE, SpecId::AMSTERDAM] {
        let block =
            drive_txs(spec, &accounts, &[DriveTx::call(EC_ADD, 1_000).with_input(input.to_vec())]);

        let trx = block.transaction_traces.first().expect("one transaction");
        let call = trx.calls.first().expect("one call");
        assert!(call.state_reverted, "{spec:?}: precompile call must be reverted");

        let transfers: Vec<_> =
            call.balance_changes.iter().filter(|b| b.reason == Reason::Transfer as i32).collect();

        assert_eq!(
            transfers.len(),
            2,
            "{spec:?}: reverted precompile value transfer must emit sender-debit + \
             precompile-credit"
        );
        assert_eq!(transfers[0].address, SENDER.to_vec(), "first transfer is the sender debit");
        assert_eq!(
            transfers[1].address,
            EC_ADD.to_vec(),
            "second transfer is the precompile credit"
        );
    }
}

/// Regression for the Base mainnet block 48387796 panic (tx 0xc2cf3e23…): a Uniswap V4
/// revert-based quote emitted a `Swap` *opcode* log inside a sub-call that then reverted, and a
/// B-20 token's committed precompile log then landed at the index the reverted log had freed.
/// Counting the reverted log would have skipped the precompile log, leaving the call one log
/// short of the receipt and making `assign_ordinal_and_index_to_receipt_logs` panic
/// ("6 call logs but 7 receipt logs").
///
/// [`CALLER`] calls [`REVERTER`], which logs and reverts, then calls the precompile, whose log
/// must be captured as the transaction's first.
#[test]
fn precompile_log_after_reverted_opcode_log_is_captured() {
    let reverter = [op_log0(), push(&[0]), push(&[0]), vec![0xfd]].concat(); // REVERT
    let caller = [op_call_with_value(REVERTER, 0), op_call_with_value(PRECOMPILE, 0)].concat();
    let block = drive_with_journal_writer(
        &[
            (SENDER, balance_account(1_000_000)),
            (CALLER, code_account(&caller, 0)),
            (REVERTER, code_account(&reverter, 0)),
            (PRECOMPILE, AccountInfo::default()),
        ],
        &[DriveTx::call(CALLER, 0)],
    );

    let trx = block.transaction_traces.first().expect("one transaction");
    let [_, reverted, precompile] = trx.calls.as_slice() else {
        panic!("expected the root call and its two sub-calls, got {}", trx.calls.len());
    };
    assert_eq!(reverted.address, REVERTER.to_vec());
    assert!(reverted.state_reverted, "the logging sub-call reverted");

    assert_eq!(precompile.address, PRECOMPILE.to_vec());
    assert_eq!(
        precompile.logs.len(),
        1,
        "precompile log reusing a reverted log's index must still be captured"
    );
    assert_eq!(precompile.logs[0].address, PRECOMPILE.to_vec());
    assert_eq!(precompile.logs[0].block_index, 0);
}
