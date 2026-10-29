//! Root call traces for transactions that halt before their first frame.
//!
//! Under EIP-2780 (Amsterdam) a transaction pays some gas at runtime before its first frame
//! opens, for example the new-account state gas of a value transfer to an empty account. When
//! that charge runs out of gas, evm2 includes the transaction as an out-of-gas halt and never
//! opens a frame (`evm2::ethereum::prepare_initial_frame` returns `None`), so no inspector hook
//! fires. The [`TracingInspector`] then keeps the default root node of its arena, and every
//! trace builder reports a call from and to the zero address.
//!
//! [`fill_unentered_root_trace`] rebuilds that root call from the transaction.
//!
//! [`TracingInspector`]: evm2_inspectors::tracing::TracingInspector

use alloy_consensus::Transaction;
use alloy_primitives::{Address, TxKind};
use evm2::{evm::TxResultExt, interpreter::InstrStop, Version};
use evm2_inspectors::tracing::{
    types::{CallKind, CallTrace},
    CallTraceArena, DebugInspector,
};

/// Returns `true` if `traces` still holds only the untouched default root of a failed
/// transaction, which means evm2 halted it before opening its first frame.
///
/// This check is cheap. Call it before looking up the transaction for
/// [`fill_unentered_root_trace`].
pub fn is_unentered_root<E>(traces: &CallTraceArena, result: &TxResultExt<E>) -> bool {
    !result.status && matches!(traces.nodes(), [root] if root.trace == CallTrace::default())
}

/// Fills the root call of a transaction that halted before evm2 opened its first frame.
///
/// The root is filled only when [`is_unentered_root`] holds. A transaction that entered
/// execution always records a root call, so this never changes the trace of one.
///
/// The filled root calls from `caller` to the recipient (or, for a create, the address the
/// creation would have used), carries the value and input, and receives the gas left after the
/// intrinsic gas. It ends out of gas, because an out-of-gas halt is the only way evm2 includes
/// a transaction without entering execution.
///
/// Returns `true` if it filled the root, `false` if it left the arena unchanged.
pub fn fill_unentered_root_trace<E>(
    traces: &mut CallTraceArena,
    caller: Address,
    tx: &impl Transaction,
    version: &Version,
    result: &TxResultExt<E>,
) -> bool {
    if !is_unentered_root(traces, result) {
        return false
    }

    let kind = tx.kind();
    let (access_list_accounts, access_list_storage_keys) =
        tx.access_list().map(evm2::ethereum::access_list_counts).unwrap_or_default();
    let (mut intrinsic, _floor) = evm2::ethereum::intrinsic_and_floor_gas(
        version,
        caller,
        kind,
        tx.input(),
        access_list_accounts,
        access_list_storage_keys,
        tx.value(),
    );
    if version.feature(evm2::EvmFeatures::EIP7702) {
        let auths = tx.authorization_list().map_or(0, |list| list.len() as u64);
        intrinsic += auths *
            version.gas_params.get(evm2::version::GasId::TxEip7702PerEmptyAccountCost);
    }
    let gas_limit = tx.gas_limit().saturating_sub(intrinsic);

    let (call_kind, address) = match kind {
        TxKind::Call(to) => (CallKind::Call, to),
        TxKind::Create => (CallKind::Create, caller.create(tx.nonce())),
    };

    let trace = &mut traces.nodes_mut()[0].trace;
    trace.depth = 0;
    trace.success = false;
    trace.caller = caller;
    trace.address = address;
    trace.kind = call_kind;
    trace.value = tx.value();
    trace.data = tx.input().clone();
    trace.gas_limit = gas_limit;
    trace.gas_used = gas_limit;
    trace.status = Some(InstrStop::OutOfGas);
    true
}

/// Applies [`fill_unentered_root_trace`] to the call traces of a [`DebugInspector`].
///
/// Call it after the transaction ran and before [`DebugInspector::get_result`]. Tracers that
/// record no call tree (`4byteTracer`, `noopTracer`, the state gas tracer, JS tracers) are left
/// alone. The `muxTracer` keeps its call traces private, so it is also left alone.
pub fn fill_unentered_debug_root<E>(
    inspector: &mut DebugInspector,
    caller: Address,
    tx: &impl Transaction,
    version: &Version,
    result: &TxResultExt<E>,
) -> bool {
    match inspector {
        DebugInspector::CallTracer(tracing, _) |
        DebugInspector::PreStateTracer(tracing, _) |
        DebugInspector::FlatCallTracer(tracing) |
        DebugInspector::Erc7562Tracer(tracing, _) |
        DebugInspector::Default(tracing, _) => {
            fill_unentered_root_trace(tracing.traces_mut(), caller, tx, version, result)
        }
        _ => false,
    }
}
