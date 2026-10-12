//! Root call traces for transactions that halt before their first frame.
//!
//! Under EIP-2780 (Amsterdam) a transaction pays some gas at runtime before its first frame
//! opens, for example the new-account state gas of a value transfer to an empty account. When
//! that charge runs out of gas, revm includes the transaction as an out-of-gas halt and never
//! opens a frame, so no inspector hook fires. The [`TracingInspector`] then keeps the default
//! root node of its arena, and every trace builder reports a call from and to the zero address.
//!
//! [`fill_unentered_root_trace`] rebuilds that root call from the transaction.
//!
//! [`TracingInspector`]: revm_inspectors::tracing::TracingInspector

use alloy_primitives::TxKind;
use revm::{
    context::{result::ExecutionResult, Cfg, Transaction},
    context_interface::cfg::gas_params::Eip2780TxInfo,
    interpreter::InstructionResult,
};
use revm_inspectors::tracing::{
    types::{CallKind, CallTrace},
    CallTraceArena, DebugInspector,
};

/// Returns `true` if `traces` still holds only the untouched default root of a failed
/// transaction, which means revm halted it before opening its first frame.
///
/// This check is cheap. Call it before building a transaction environment for
/// [`fill_unentered_root_trace`].
pub fn is_unentered_root<H>(traces: &CallTraceArena, result: &ExecutionResult<H>) -> bool {
    !result.is_success() && matches!(traces.nodes(), [root] if root.trace == CallTrace::default())
}

/// Fills the root call of a transaction that halted before revm opened its first frame.
///
/// The root is filled only when [`is_unentered_root`] holds. A transaction that entered
/// execution always records a root call, so this never changes the trace of one.
///
/// The filled root calls from the sender to the recipient (or, for a create, the address the
/// creation would have used), carries the value and input, and receives the gas left after the
/// intrinsic gas. It ends out of gas, because an out-of-gas halt is the only way revm includes
/// a transaction without entering execution.
///
/// Returns `true` if it filled the root, `false` if it left the arena unchanged.
pub fn fill_unentered_root_trace<H>(
    traces: &mut CallTraceArena,
    tx: &impl Transaction,
    cfg: &impl Cfg,
    result: &ExecutionResult<H>,
) -> bool {
    if !is_unentered_root(traces, result) {
        return false
    }

    let caller = tx.caller();
    let kind = tx.kind();
    let eip2780 = cfg
        .is_amsterdam_eip2780_enabled()
        .then(|| Eip2780TxInfo { value: tx.value(), is_self_transfer: kind.to() == Some(&caller) });
    let initial = cfg.gas_params().initial_tx_gas_for_tx(tx, eip2780);
    let gas_limit = tx
        .gas_limit()
        .saturating_sub(initial.initial_regular_gas)
        .saturating_sub(initial.initial_state_gas);

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
    trace.status = Some(InstructionResult::OutOfGas);
    true
}

/// Applies [`fill_unentered_root_trace`] to the call traces of a [`DebugInspector`].
///
/// Call it after the transaction ran and before [`DebugInspector::get_result`]. Tracers that
/// record no call tree (`4byteTracer`, `noopTracer`, the state gas tracer, JS tracers) are left
/// alone. The `muxTracer` keeps its call traces private, so it is also left alone.
pub fn fill_unentered_debug_root<H>(
    inspector: &mut DebugInspector,
    tx: &impl Transaction,
    cfg: &impl Cfg,
    result: &ExecutionResult<H>,
) -> bool {
    match inspector {
        DebugInspector::CallTracer(tracing, _) |
        DebugInspector::PreStateTracer(tracing, _) |
        DebugInspector::FlatCallTracer(tracing) |
        DebugInspector::Erc7562Tracer(tracing, _) |
        DebugInspector::Default(tracing, _) => {
            fill_unentered_root_trace(tracing.traces_mut(), tx, cfg, result)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, U256};
    use revm::{
        context::{CfgEnv, Context, TxEnv},
        database::InMemoryDB,
        primitives::hardfork::SpecId,
        state::AccountInfo,
        InspectEvm, MainBuilder, MainContext,
    };
    use revm_inspectors::tracing::{TracingInspector, TracingInspectorConfig};

    const SENDER: Address = Address::repeat_byte(0x51);
    const RECIPIENT: Address = Address::repeat_byte(0x7e);

    fn transfer(gas_limit: u64) -> TxEnv {
        TxEnv {
            caller: SENDER,
            kind: TxKind::Call(RECIPIENT),
            value: U256::from(1_000_000_000u64),
            gas_limit,
            gas_price: 0,
            gas_priority_fee: Some(0),
            tx_type: 2,
            ..Default::default()
        }
    }

    /// Runs `tx` from [`SENDER`] on an Amsterdam EVM and returns the inspector and result.
    fn run(tx: &TxEnv, spec: SpecId) -> (TracingInspector, ExecutionResult, CfgEnv) {
        let mut db = InMemoryDB::default();
        db.insert_account_info(
            SENDER,
            AccountInfo { balance: U256::from(10u128.pow(18)), ..Default::default() },
        );
        let cfg = CfgEnv::<SpecId>::default().with_spec_and_mainnet_gas_params(spec);
        let mut evm = Context::mainnet()
            .with_cfg(cfg.clone())
            .modify_block_chained(|block| block.basefee = 0)
            .with_db(db)
            .build_mainnet_with_inspector(TracingInspector::new(
                TracingInspectorConfig::default_parity(),
            ));
        let result = evm.inspect_tx(tx.clone()).unwrap().result;
        (evm.inspector.clone(), result, cfg)
    }

    #[test]
    fn transfer_to_empty_account_out_of_state_gas_traces_sender_and_recipient() {
        let tx = transfer(30_000);
        let (mut inspector, result, cfg) = run(&tx, SpecId::AMSTERDAM);
        assert!(!result.is_success(), "the new-account state gas must not fit in 30,000 gas");
        assert_eq!(result.tx_gas_used(), 30_000);
        // The bug: revm opened no frame, so the root is the arena's untouched default.
        assert_eq!(inspector.traces().nodes().len(), 1);
        assert_eq!(inspector.traces().nodes()[0].trace, Default::default());

        assert!(fill_unentered_root_trace(inspector.traces_mut(), &tx, &cfg, &result));

        let traces = inspector.into_parity_builder().into_transaction_traces();
        assert_eq!(traces.len(), 1);
        let root = &traces[0];
        let alloy_rpc_types_trace::parity::Action::Call(call) = &root.action else {
            panic!("expected a call action, got {:?}", root.action)
        };
        assert_eq!(call.from, SENDER);
        assert_eq!(call.to, RECIPIENT);
        assert_eq!(call.value, tx.value);
        // The frame would have received the gas left after the 21,000 intrinsic gas.
        assert_eq!(call.gas, 30_000 - 21_000);
        assert_eq!(root.error.as_deref(), Some("Out of gas"));
        assert!(root.result.is_none());
        assert!(root.trace_address.is_empty());
        assert_eq!(root.subtraces, 0);
    }

    #[test]
    fn transfer_that_enters_execution_is_left_alone() {
        let tx = transfer(30_000);
        // Before Amsterdam the same transfer succeeds and opens a frame.
        let (mut inspector, result, cfg) = run(&tx, SpecId::PRAGUE);
        assert!(result.is_success());
        let before = inspector.traces().nodes().to_vec();

        assert!(!fill_unentered_root_trace(inspector.traces_mut(), &tx, &cfg, &result));
        assert_eq!(inspector.traces().nodes(), &before[..]);
    }
}
