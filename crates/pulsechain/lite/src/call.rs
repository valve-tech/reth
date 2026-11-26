//! `eth_call` and `eth_estimateGas` over partial state.
//!
//! Message building: `from` defaults to the zero address, the
//! `eth_call` gas defaults to and is clamped by the gas cap, the effective gas price follows the
//! 1559 rule when a base fee exists, `input` wins over `data`, and nonce and sender-is-EOA checks
//! are skipped. As in geth, only a call with a zero gas price runs with a zero base fee and without
//! fee and balance checks; a priced call pays for its gas limit up front. An access list is charged
//! and warmed as in a type-1 transaction. The EVM is `evm2` through the Ethereum EVM configuration
//! of reth; the block environment comes from the header of the block the call runs at.
//!
//! `PulseChain` differs from Ethereum in the chain ID before `PrimordialPulse` and in how it
//! replays Ethereum history. A lite node serves recent blocks only (at most a few hundred behind
//! the head, long after `PrimordialPulse`), so none of that applies here and the stock Ethereum
//! configuration over the `PulseChain` fork schedule is exact.

use crate::{
    config::OnMiss,
    exec::{run_rounds_blocking, Fetcher, RoundsError, WarmSink},
    state::{BlockHashes, MissingDb, PartialState},
    store::NodeStore,
};
use alloy_consensus::{
    constants::KECCAK_EMPTY,
    transaction::{Recovered, Transaction},
    Header, TxEip1559, TxEip2930, TxLegacy,
};
use alloy_primitives::{Address, Bytes, TxKind, U256};
use alloy_rpc_types_eth::TransactionRequest;
use evm2::{
    ethereum::TxEnvelope,
    evm::Database,
    interpreter::{op, Interpreter},
    registry::HandlerError,
    EvmFeatures, EvmTypesHost, ExecutionError, Inspector, InspectorConfig, OpcodeSet,
};
use reth_chainspec::ChainSpec;
use reth_evm::{ConfigureEvm, EvmEnv, EvmEnvFor};
use reth_evm_ethereum::EthEvmConfig;
use std::{
    sync::{Arc, Weak},
    time::{Duration, Instant},
};

/// The gas cap of `eth_call` and `eth_estimateGas`.
pub const GAS_CAP: u64 = 50_000_000;

/// The EVM time limit of one call, geth's `--rpc.evmtimeout` default.
pub const DEFAULT_EVM_TIMEOUT: Duration = Duration::from_secs(5);

/// EVM runs at once. Each holds a blocking thread for up to the gas cap's worth of work.
pub const MAX_CONCURRENT_EXECUTIONS: usize = 4;

/// The intrinsic gas of a plain transfer (geth's `params.TxGas`).
const TX_GAS: u64 = 21_000;

/// The gas a value transfer passes to its callee (geth's `params.CallStipend`).
const CALL_STIPEND: u64 = 2_300;

/// Relative tolerance of the gas estimate search.
const ERROR_RATIO: f64 = 0.015;

/// What a call produced when state was complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallOutcome {
    /// Returned normally.
    Success(Bytes),
    /// `REVERT`, with the revert data.
    Revert {
        /// The revert data.
        data: Bytes,
    },
}

/// Why a call did not produce an outcome.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CallError {
    /// The request is malformed.
    #[error("{0}")]
    Invalid(String),
    /// Execution halted (out of gas, invalid opcode, ...) with complete state.
    #[error("{0}")]
    Halted(String),
    /// Execution of an estimate reverted.
    #[error("execution reverted")]
    EstimateReverted(Bytes),
    /// The EVM refused the transaction.
    #[error("{0}")]
    Evm(String),
    /// The EVM ran past the limit, geth's `--rpc.evmtimeout`.
    #[error("execution aborted (timeout = {})", go_duration(*.0))]
    Timeout(Duration),
    /// State was missing (or fetching failed).
    #[error(transparent)]
    Rounds(#[from] RoundsError),
}

/// Everything a call needs besides the request and the block.
#[derive(Clone)]
pub struct ExecCtx {
    /// The EVM configuration for the chain's fork schedule.
    pub evm: EthEvmConfig<ChainSpec>,
    /// The chain id.
    pub chain_id: u64,
    /// The verified node store.
    pub store: Arc<dyn NodeStore>,
    /// `BLOCKHASH` source.
    pub hashes: BlockHashes,
    /// Where misses are fetched from.
    pub fetcher: Arc<dyn Fetcher>,
    /// Background warming, in `error-and-warm`.
    pub warm: Option<Arc<dyn WarmSink>>,
    /// What to do on a miss.
    pub mode: OnMiss,
    /// Maximum rounds.
    pub max_rounds: u32,
    /// Gas cap.
    pub gas_cap: u64,
    /// EVM runs at once, each on a blocking thread.
    pub exec_permits: Arc<tokio::sync::Semaphore>,
    /// The EVM time limit of one call; zero sets no limit.
    pub evm_timeout: Duration,
}

impl std::fmt::Debug for ExecCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecCtx").field("chain_id", &self.chain_id).finish_non_exhaustive()
    }
}

impl ExecCtx {
    /// A context for chain `chain_id` (369 or 943).
    pub fn new(
        chain_id: u64,
        store: Arc<dyn NodeStore>,
        hashes: BlockHashes,
        fetcher: Arc<dyn Fetcher>,
        mode: OnMiss,
        max_rounds: u32,
    ) -> Option<Self> {
        let spec = match chain_id {
            reth_pulsechain_forks::chainspec::PULSECHAIN_MAINNET_CHAIN_ID => {
                reth_pulsechain_forks::chainspec::PULSECHAIN.clone()
            }
            reth_pulsechain_forks::chainspec::PULSECHAIN_TESTNET_V4_CHAIN_ID => {
                reth_pulsechain_forks::chainspec::PULSECHAIN_TESTNET_V4.clone()
            }
            _ => return None,
        };
        Some(Self {
            evm: EthEvmConfig::new(spec),
            chain_id,
            store,
            hashes,
            fetcher,
            warm: None,
            mode,
            max_rounds,
            gas_cap: GAS_CAP,
            exec_permits: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_EXECUTIONS)),
            evm_timeout: DEFAULT_EVM_TIMEOUT,
        })
    }

    /// The same context with a warm sink.
    pub fn with_warm(mut self, warm: Arc<dyn WarmSink>) -> Self {
        self.warm = Some(warm);
        self
    }
}

/// The effective gas price, as geth's `CallDefaults` and `ToMessage` set it: `gasPrice` as given,
/// else the tip plus the base fee capped by the fee cap, a missing 1559 field being zero.
fn effective_gas_price(req: &TransactionRequest, base_fee: Option<u64>) -> Result<u128, CallError> {
    let has_1559 = req.max_fee_per_gas.is_some() || req.max_priority_fee_per_gas.is_some();
    if req.gas_price.is_some() && has_1559 {
        return Err(CallError::Invalid(
            "both gasPrice and (maxFeePerGas or maxPriorityFeePerGas) specified".into(),
        ));
    }
    if let Some(p) = req.gas_price {
        return Ok(p);
    }
    // geth's CallDefaults: a missing fee field is 0, not uncapped.
    let fee_cap = req.max_fee_per_gas.unwrap_or(0);
    let tip = req.max_priority_fee_per_gas.unwrap_or(0);
    if fee_cap == 0 && tip == 0 {
        return Ok(0);
    }
    if tip > fee_cap {
        return Err(CallError::Invalid(
            "max priority fee per gas higher than max fee per gas".into(),
        ));
    }
    Ok(tip.saturating_add(u128::from(base_fee.unwrap_or(0))).min(fee_cap))
}

fn build_tx(
    ctx: &ExecCtx,
    req: &TransactionRequest,
    header: &Header,
    gas: u64,
) -> Result<Recovered<TxEnvelope>, CallError> {
    if let Some(have) = req.chain_id &&
        have != ctx.chain_id
    {
        return Err(CallError::Invalid(format!(
            "chainId does not match node's (have={have}, want={})",
            ctx.chain_id
        )));
    }
    // PulseChain schedules neither Cancun nor Prague, so no handler exists for these.
    if req.blob_versioned_hashes.as_ref().is_some_and(|h| !h.is_empty()) {
        return Err(CallError::Invalid("blobVersionedHashes are not supported".into()));
    }
    if req.authorization_list.as_ref().is_some_and(|l| !l.is_empty()) {
        return Err(CallError::Invalid("authorizationList is not supported".into()));
    }
    let gas_price = effective_gas_price(req, header.base_fee_per_gas)?;
    let input = req.input.input.clone().or_else(|| req.input.data.clone()).unwrap_or_default();
    let to = req.to.unwrap_or(TxKind::Create);
    let value = req.value.unwrap_or(U256::ZERO);
    let tx = if req.max_fee_per_gas.is_some() || req.max_priority_fee_per_gas.is_some() {
        // The 1559 form checks the balance against the fee cap, as geth's buyGas does.
        TxEnvelope::Eip1559(TxEip1559 {
            chain_id: ctx.chain_id,
            nonce: 0,
            gas_limit: gas,
            max_fee_per_gas: req.max_fee_per_gas.unwrap_or(0),
            max_priority_fee_per_gas: req.max_priority_fee_per_gas.unwrap_or(0),
            to,
            value,
            access_list: req.access_list.clone().unwrap_or_default(),
            input,
        })
    } else if let Some(list) = &req.access_list {
        // The 2930 form charges and warms the list, as geth does for a call with one.
        TxEnvelope::Eip2930(TxEip2930 {
            chain_id: ctx.chain_id,
            nonce: 0,
            gas_price,
            gas_limit: gas,
            to,
            value,
            access_list: list.clone(),
            input,
        })
    } else {
        TxEnvelope::Legacy(TxLegacy {
            chain_id: None,
            nonce: 0,
            gas_price,
            gas_limit: gas,
            to,
            value,
            input,
        })
    };
    Ok(Recovered::new_unchecked(tx, req.from.unwrap_or_default()))
}

/// The EVM environment of a call that pays `gas_price` per gas.
fn call_env(
    ctx: &ExecCtx,
    header: &Header,
    gas_price: u128,
) -> Result<EvmEnvFor<EthEvmConfig<ChainSpec>>, CallError> {
    let mut env = ctx.evm.evm_env(header).map_err(|e| CallError::Evm(e.to_string()))?;
    {
        let f = &mut env.version_mut().features;
        // Mirrors geth's SkipAccountChecks for calls.
        f.remove(EvmFeatures::BLOCK_GAS_LIMIT_CHECK);
        f.remove(EvmFeatures::EIP3607);
        f.remove(EvmFeatures::NONCE_CHECK);
        // geth's NoBaseFee relaxes fees only for a free call: a priced one pays for its gas.
        if gas_price == 0 {
            f.remove(EvmFeatures::BASE_FEE_CHECK);
            f.remove(EvmFeatures::FEE_CHARGE);
            f.remove(EvmFeatures::BALANCE_CHECK | EvmFeatures::BALANCE_TOP_UP);
        }
    }
    if !env.version().feature(EvmFeatures::EIP8037) {
        env.version_mut().tx_gas_limit_cap = u64::MAX;
    }
    if gas_price == 0 {
        env.block_env_mut().basefee = U256::ZERO;
    }
    Ok(env)
}

/// The opcodes the [`Watchdog`] steps on: every loop passes a jump, and every chain of frames
/// passes a call or a create.
const WATCHED: OpcodeSet = {
    let ops = [
        op::JUMP,
        op::JUMPI,
        op::CALL,
        op::CALLCODE,
        op::DELEGATECALL,
        op::STATICCALL,
        op::CREATE,
        op::CREATE2,
    ];
    let mut set = OpcodeSet::EMPTY;
    let mut i = 0;
    while i < ops.len() {
        set.insert(ops[i]);
        i += 1;
    }
    set
};

/// Watched steps between two reads of the clock and the caller.
const CHECK_EVERY: u32 = 1024;

/// Why a [`Watchdog`] stopped a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stop {
    /// The deadline passed.
    Timeout,
    /// The caller stopped waiting.
    CallerGone,
}

/// Stops the EVM runs of one call at the call's deadline, or once its caller has gone, so a
/// stopped run frees its blocking thread and its execution permit at once.
struct Watchdog {
    deadline: Option<Instant>,
    caller: Option<Weak<()>>,
    steps: u32,
    stop: Option<Stop>,
}

impl Watchdog {
    /// A watchdog for the caller of `db`, with a deadline `timeout` from now. A zero `timeout`
    /// sets no deadline.
    fn new(db: &MissingDb, timeout: Duration) -> Self {
        Self {
            deadline: (!timeout.is_zero()).then(|| Instant::now() + timeout),
            caller: db.caller().cloned(),
            steps: 0,
            stop: None,
        }
    }

    fn check(&self) -> Option<Stop> {
        if self.caller.as_ref().is_some_and(|c| c.strong_count() == 0) {
            return Some(Stop::CallerGone);
        }
        self.deadline.is_some_and(|d| Instant::now() >= d).then_some(Stop::Timeout)
    }
}

impl<T: EvmTypesHost> Inspector<T> for Watchdog {
    fn inspector_config(&self) -> InspectorConfig {
        InspectorConfig::without_steps().with_steps(WATCHED)
    }

    fn step(&mut self, interp: &mut Interpreter<'_, '_, T>) {
        self.steps = self.steps.wrapping_add(1);
        if self.stop.is_none() && self.steps.is_multiple_of(CHECK_EVERY) {
            self.stop = self.check();
        }
        if self.stop.is_some() {
            // A step hook sets the stop as well as the error, as evm2's JavaScript tracer does.
            let stop = interp.fail(ExecutionError::Fatal("stopped by the watchdog".into()));
            interp.set_stop(stop);
        }
    }
}

/// One execution. Misses are recorded in `db` and the result is meaningless if there are any.
struct Run {
    outcome: Result<CallOutcome, CallError>,
    gas_used: u64,
    /// The gas used before the refund (geth's `MaxUsedGas`).
    peak_gas: u64,
    /// The run halted out of gas, or its limit was below the intrinsic gas.
    out_of_gas: bool,
}

fn execute(
    ctx: &ExecCtx,
    env: &EvmEnvFor<EthEvmConfig<ChainSpec>>,
    db: &mut MissingDb,
    tx: &Recovered<TxEnvelope>,
    watchdog: &mut Watchdog,
) -> Run {
    let mut evm = ctx.evm.evm_with_env(&mut *db, env.clone());
    evm.set_inspector(&mut *watchdog);
    let executed = evm.transact(tx).map(|executed| executed.discard());
    drop(evm);
    if let Some(stop) = watchdog.stop {
        let outcome = match stop {
            Stop::Timeout => CallError::Timeout(ctx.evm_timeout),
            // No one reads it.
            Stop::CallerGone => CallError::Rounds(RoundsError::Aborted),
        };
        return Run { outcome: Err(outcome), gas_used: 0, peak_gas: 0, out_of_gas: false };
    }
    let res = match executed {
        Ok(res) => res,
        Err(e) => {
            let out_of_gas = matches!(e, HandlerError::IntrinsicGasTooLow { .. });
            // geth's wording for the errors wallets classify by message.
            let message = match e {
                HandlerError::IntrinsicGasTooLow { required, got } => {
                    format!("intrinsic gas too low: have {got}, want {required}")
                }
                HandlerError::InsufficientFunds { fee, balance } => {
                    insufficient_funds(tx.signer(), balance, fee)
                }
                HandlerError::FeeCapLessThanBaseFee { max_fee_per_gas, base_fee } => format!(
                    "max fee per gas less than block base fee: address {}, maxFeePerGas: \
                     {max_fee_per_gas}, baseFee: {base_fee}",
                    tx.signer()
                ),
                other => other.to_string(),
            };
            return Run {
                outcome: Err(CallError::Evm(message)),
                gas_used: 0,
                peak_gas: 0,
                out_of_gas,
            };
        }
    };
    let gas_used = res.tx_gas_used();
    let peak_gas = res.total_gas_spent.max(gas_used);
    let mut out_of_gas = false;
    use evm2::interpreter::InstrStop as S;
    let outcome = if res.is_success() {
        Ok(CallOutcome::Success(res.output))
    } else if res.is_revert() {
        Ok(CallOutcome::Revert { data: res.output })
    } else if res.stop == S::OutOfFunds {
        // Only the top frame's stop reaches here, so the sender cannot pay the call's value. A
        // free call skips the handler's balance check; geth reports this one as its own.
        let Ok(sender) = db.get_account(&tx.signer());
        let balance = sender.map(|a| a.balance).unwrap_or_default();
        Err(CallError::Evm(insufficient_funds(tx.signer(), balance, tx.value())))
    } else {
        // geth's core/vm error strings.
        Err(CallError::Halted(match res.stop {
            S::OutOfGas |
            S::MemoryOOG |
            S::MemoryLimitOOG |
            S::PrecompileOOG |
            S::InvalidOperandOOG => {
                out_of_gas = true;
                "out of gas".into()
            }
            S::ReentrancySentryOOG => "not enough gas for reentrancy sentry".into(),
            S::OpcodeNotFound | S::InvalidFEOpcode | S::NotActivated => "invalid opcode".into(),
            S::InvalidJump => "invalid jump destination".into(),
            S::StackUnderflow => "stack underflow".into(),
            S::StackOverflow => "stack limit reached 1024".into(),
            S::OutOfOffset => "return data out of bounds".into(),
            S::CallTooDeep => "max call depth exceeded".into(),
            S::NonceOverflow => "nonce uint64 overflow".into(),
            S::CallNotAllowedInsideStatic | S::StateChangeDuringStaticCall => {
                "write protection".into()
            }
            S::CreateCollision => "contract address collision".into(),
            S::CreateContractSizeLimit => "max code size exceeded".into(),
            S::CreateContractStartingWithEF => "invalid code: must not begin with 0xef".into(),
            S::CreateInitCodeSizeLimit => "max initcode size exceeded".into(),
            other => format!("execution halted: {other:?}"),
        }))
    };
    Run { outcome, gas_used, peak_gas, out_of_gas }
}

/// `d` as Go's `time.Duration.String` writes it, as geth prints its timeout: `5s`, `1m30s`,
/// `250ms`.
fn go_duration(d: Duration) -> String {
    // Go's durations are whole nanoseconds; the flags cap them at a day.
    let ns = u64::try_from(d.as_nanos()).unwrap_or(u64::MAX);
    // The whole part of `v / 10^digits` and its fraction without trailing zeros, dot included.
    let split = |v: u64, digits: u32| {
        let unit = 10u64.pow(digits);
        let frac = format!("{:0width$}", v % unit, width = digits as usize);
        let frac = frac.trim_end_matches('0');
        (v / unit, if frac.is_empty() { String::new() } else { format!(".{frac}") })
    };
    let (digits, unit) = match ns {
        0 => return "0s".into(),
        1..1_000 => (0, "ns"),
        1_000..1_000_000 => (3, "µs"),
        1_000_000..1_000_000_000 => (6, "ms"),
        _ => {
            let (secs, frac) = split(ns, 9);
            let (h, m, s) = (secs / 3600, secs / 60 % 60, secs % 60);
            return match (h, m) {
                (0, 0) => format!("{s}{frac}s"),
                (0, _) => format!("{m}m{s}{frac}s"),
                _ => format!("{h}h{m}m{s}{frac}s"),
            };
        }
    };
    let (whole, frac) = split(ns, digits);
    format!("{whole}{frac}{unit}")
}

/// geth's `ErrInsufficientFunds` message: `want` is the value plus the gas limit at the fee cap.
fn insufficient_funds(sender: Address, have: U256, want: U256) -> String {
    format!("insufficient funds for gas * price + value: address {sender} have {have} want {want}")
}

/// `eth_call` at `header`'s post-state.
pub async fn eth_call(
    ctx: &ExecCtx,
    req: TransactionRequest,
    header: &Header,
) -> Result<CallOutcome, CallError> {
    let gas = req.gas.unwrap_or(ctx.gas_cap).min(ctx.gas_cap);
    let env = call_env(ctx, header, effective_gas_price(&req, header.base_fee_per_gas)?)?;
    let tx = build_tx(ctx, &req, header, gas)?;
    let state = PartialState::new(ctx.store.clone(), header.state_root);
    let run_ctx = ctx.clone();
    let out = run_rounds_blocking(
        &state,
        &ctx.hashes,
        &*ctx.fetcher,
        ctx.warm.as_deref(),
        ctx.mode,
        ctx.max_rounds,
        &ctx.exec_permits,
        move |db| {
            let mut watchdog = Watchdog::new(db, run_ctx.evm_timeout);
            execute(&run_ctx, &env, db, &tx, &mut watchdog).outcome
        },
    )
    .await?;
    // geth's `eth_call` wraps the errors of applying the message in its own form.
    out.value.map_err(|e| match e {
        CallError::Evm(m) => CallError::Evm(format!("err: {m} (supplied gas {gas})")),
        other => other,
    })
}

/// `eth_estimateGas` at `header`'s post-state: go-ethereum's search (`eth/gasestimator`), run
/// inside one round so a miss anywhere discards the whole search.
///
/// As in geth, the upper bound is the request's gas if it is at least a transfer's, else the
/// block gas limit, capped by the gas cap and, for a priced call, by what the sender can pay. A
/// plain transfer tries 21000 first. Otherwise the search runs at the upper bound, then at the
/// optimistic limit `(peak used + 2300) * 64 / 63`, then bisects with the midpoint capped at
/// twice the lower bound until the range is within the 1.5% error ratio.
///
/// As in go-pulse (`padResult`) and pulse-reth, the answer is the limit found plus a fifth, capped
/// by the gas the sender can pay for at the fee cap. Upstream geth returns the limit unpadded.
pub async fn eth_estimate_gas(
    ctx: &ExecCtx,
    req: TransactionRequest,
    header: &Header,
) -> Result<u64, CallError> {
    let hi_start =
        req.gas.filter(|gas| *gas >= TX_GAS).unwrap_or(header.gas_limit).min(ctx.gas_cap);
    let env = call_env(ctx, header, effective_gas_price(&req, header.base_fee_per_gas)?)?;
    // geth divides the sender's balance by the fee cap, not by the price paid.
    let fee_cap = req.gas_price.or(req.max_fee_per_gas).unwrap_or(0);
    let state = PartialState::new(ctx.store.clone(), header.state_root);
    // The request is validated once here, even though the search varies only the limit.
    build_tx(ctx, &req, header, hi_start)?;
    let (run_ctx, header_owned) = (ctx.clone(), header.clone());
    let out = run_rounds_blocking(
        &state,
        &ctx.hashes,
        &*ctx.fetcher,
        ctx.warm.as_deref(),
        ctx.mode,
        ctx.max_rounds,
        &ctx.exec_permits,
        move |db| -> Result<u64, CallError> {
            let (ctx, header) = (&run_ctx, &header_owned);
            // One deadline for the whole search, as geth applies one to the call.
            let mut watchdog = Watchdog::new(db, ctx.evm_timeout);
            // `None` once the round has a miss (the driver discards the round) or the caller
            // has gone: no one reads the rest of the search.
            let mut try_gas = |db: &mut MissingDb, gas: u64| -> Result<Option<Run>, CallError> {
                let tx = build_tx(ctx, &req, header, gas)?;
                let run = execute(ctx, &env, db, &tx, &mut watchdog);
                if db.has_misses() || db.caller_gone() {
                    return Ok(None);
                }
                // A run past the deadline ends the search, at any step of it.
                if let Err(timeout @ CallError::Timeout(_)) = run.outcome {
                    return Err(timeout);
                }
                Ok(Some(run))
            };
            // The gas the sender can pay for at the fee cap; a free call pays for none.
            let allowance = if fee_cap == 0 {
                None
            } else {
                let Ok(sender) = db.get_account(&req.from.unwrap_or_default());
                let balance = sender.map(|a| a.balance).unwrap_or_default();
                // geth refuses a value that leaves nothing, a missing value being zero.
                let value = req.value.unwrap_or_default();
                if value >= balance {
                    return Err(CallError::Evm("insufficient funds for transfer".into()));
                }
                Some((balance - value) / U256::from(fee_cap))
            };
            let mut hi = hi_start;
            if let Some(allowance) = allowance {
                hi = hi.min(allowance.saturating_to());
            }
            // go-pulse adds a fifth to the limit found, capped by an allowance that is not zero and
            // fits a u64.
            let pad_cap = allowance.and_then(|a| u64::try_from(a).ok()).filter(|a| *a != 0);
            let pad = |gas: u64| {
                let padded = gas.saturating_add(gas / 5);
                pad_cap.map_or(padded, |cap| padded.min(cap))
            };
            if let Some(TxKind::Call(to)) = req.to &&
                req.input.input().is_none_or(|input| input.is_empty())
            {
                let Ok(callee) = db.get_account(&to);
                if callee.is_none_or(|a| a.code_hash == KECCAK_EMPTY) {
                    let Some(run) = try_gas(db, TX_GAS)? else { return Ok(TX_GAS) };
                    if matches!(run.outcome, Ok(CallOutcome::Success(_))) {
                        return Ok(pad(TX_GAS));
                    }
                }
            }
            let Some(first) = try_gas(db, hi)? else { return Ok(hi) };
            match first.outcome {
                _ if first.out_of_gas => {
                    return Err(CallError::Halted(format!("gas required exceeds allowance ({hi})")));
                }
                // geth wraps an error of applying the message with the limit of the run.
                Err(CallError::Evm(m)) => {
                    return Err(CallError::Evm(format!("failed with {hi} gas: {m}")));
                }
                Err(e) => return Err(e),
                Ok(CallOutcome::Revert { data }) => return Err(CallError::EstimateReverted(data)),
                Ok(CallOutcome::Success(_)) => {}
            }
            let mut lo = first.gas_used.saturating_sub(1);
            // The headroom covers the refund, a stipend and the 1/64 a call keeps back.
            let optimistic = first.peak_gas.saturating_add(CALL_STIPEND).saturating_mul(64) / 63;
            if optimistic < hi {
                let Some(run) = try_gas(db, optimistic)? else { return Ok(optimistic) };
                match run.outcome {
                    Ok(CallOutcome::Success(_)) => hi = optimistic,
                    _ => lo = optimistic,
                }
            }
            while lo + 1 < hi {
                if (hi - lo) as f64 / (hi as f64) < ERROR_RATIO {
                    break;
                }
                // Most calls need little more than they use, so the bisection favours the low side.
                let mid = (lo + (hi - lo) / 2).min(lo.saturating_mul(2));
                let Some(run) = try_gas(db, mid)? else { return Ok(mid) };
                match run.outcome {
                    Ok(CallOutcome::Success(_)) => hi = mid,
                    _ => lo = mid,
                }
            }
            Ok(pad(hi))
        },
    )
    .await?;
    out.value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        store::Store,
        testing::{world, Acct, Honest},
    };
    use alloy_eips::eip2930::{AccessList, AccessListItem};
    use alloy_primitives::{address, Address, B256};
    use std::sync::{atomic::Ordering, Arc};

    const ALICE: Address = address!("00000000000000000000000000000000000a11ce");
    const BOB: Address = address!("0000000000000000000000000000000000000b0b");
    const VIEW: Address = address!("00000000000000000000000000000000000c0de1");
    const REVERTER: Address = address!("00000000000000000000000000000000000c0de2");
    const SPINNER: Address = address!("00000000000000000000000000000000000c0de3");
    const SLOADER: Address = address!("00000000000000000000000000000000000c0de4");
    const HEAVY: Address = address!("00000000000000000000000000000000000c0de5");
    const DELEGATED: Address = address!("00000000000000000000000000000000000e0a01");
    const FEE_READER: Address = address!("00000000000000000000000000000000000c0de6");
    const BAD_JUMP: Address = address!("00000000000000000000000000000000000c0de7");
    const UNDERFLOW: Address = address!("00000000000000000000000000000000000c0de8");
    const CLEARER: Address = address!("00000000000000000000000000000000000c0de9");

    fn setup(mode: OnMiss) -> (ExecCtx, Header, Arc<Honest>) {
        let w = Arc::new(world(&[
            (ALICE, Acct { balance: 10_u64.pow(18), ..Default::default() }),
            (BOB, Acct { balance: 1, ..Default::default() }),
            // PUSH1 0x2a PUSH1 0 MSTORE PUSH1 0x20 PUSH1 0 RETURN
            (
                VIEW,
                Acct {
                    code: vec![0x60, 0x2a, 0x60, 0, 0x52, 0x60, 0x20, 0x60, 0, 0xf3],
                    ..Default::default()
                },
            ),
            // PUSH1 0xde PUSH1 0 MSTORE8 PUSH1 1 PUSH1 0 REVERT
            (
                REVERTER,
                Acct {
                    code: vec![0x60, 0xde, 0x60, 0, 0x53, 0x60, 1, 0x60, 0, 0xfd],
                    ..Default::default()
                },
            ),
            // JUMPDEST PUSH1 0 JUMP
            (SPINNER, Acct { code: vec![0x5b, 0x60, 0, 0x56], ..Default::default() }),
            // PUSH1 7 SLOAD PUSH1 0 MSTORE PUSH1 0x20 PUSH1 0 RETURN
            (
                SLOADER,
                Acct {
                    code: vec![0x60, 7, 0x54, 0x60, 0, 0x52, 0x60, 0x20, 0x60, 0, 0xf3],
                    storage: vec![
                        (U256::from(7), U256::from(1234)),
                        (U256::from(8), U256::from(1)),
                    ],
                    ..Default::default()
                },
            ),
            // An EIP-7702 delegation designator pointing at VIEW.
            (
                DELEGATED,
                Acct {
                    code: [&[0xef, 0x01, 0x00], VIEW.as_slice()].concat(),
                    ..Default::default()
                },
            ),
            // BASEFEE GASPRICE ORIGIN BALANCE, stored at 0x00, 0x20 and 0x40 and returned.
            (
                FEE_READER,
                Acct {
                    code: vec![
                        0x48, 0x60, 0, 0x52, 0x3a, 0x60, 0x20, 0x52, 0x32, 0x31, 0x60, 0x40, 0x52,
                        0x60, 0x60, 0x60, 0, 0xf3,
                    ],
                    ..Default::default()
                },
            ),
            // PUSH1 0 JUMP: offset 0 is not a JUMPDEST.
            (BAD_JUMP, Acct { code: vec![0x60, 0, 0x56], ..Default::default() }),
            // ADD on an empty stack.
            (UNDERFLOW, Acct { code: vec![0x01], ..Default::default() }),
            // PUSH1 0 PUSH1 8 SSTORE STOP: clears slot 8, which earns a refund.
            (
                CLEARER,
                Acct {
                    code: vec![0x60, 0, 0x60, 8, 0x55, 0x00],
                    storage: vec![(U256::from(8), U256::from(1))],
                    ..Default::default()
                },
            ),
            // 100 SSTOREs of nonzero values into fresh slots: gas well above the intrinsic floor.
            (HEAVY, {
                let mut code = Vec::new();
                for i in 1u8..=40 {
                    code.extend([0x60, i, 0x60, i, 0x55]);
                }
                code.push(0x00);
                Acct { code, ..Default::default() }
            }),
        ]));
        let store: Arc<dyn NodeStore> = Arc::new(Store::in_memory(1 << 24));
        let honest = Arc::new(Honest::new(w.clone(), store.clone()));
        let hashes: BlockHashes = Arc::new(|_| None);
        let ctx = ExecCtx::new(943, store, hashes, honest.clone(), mode, 40).unwrap();
        let header = Header {
            number: 1_000_000,
            timestamp: 1_800_000_000,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(1_000),
            state_root: w.root,
            excess_blob_gas: Some(0),
            blob_gas_used: Some(0),
            withdrawals_root: Some(alloy_consensus::constants::EMPTY_WITHDRAWALS),
            parent_beacon_block_root: Some(B256::ZERO),
            requests_hash: Some(alloy_eips::eip7685::EMPTY_REQUESTS_HASH),
            ..Default::default()
        };
        (ctx, header, honest)
    }

    fn call_to(to: Address) -> TransactionRequest {
        TransactionRequest { to: Some(TxKind::Call(to)), ..Default::default() }
    }

    /// A warm sink that keeps what it is given.
    struct Queue(std::sync::Mutex<Vec<crate::state::MissKey>>);

    impl WarmSink for Queue {
        fn warm(&self, _: B256, misses: Vec<crate::state::MissKey>) {
            self.0.lock().unwrap().extend(misses);
        }
    }

    /// geth's `eth_call` form of an error from applying the message.
    fn call_err(message: &str, gas: u64) -> CallError {
        CallError::Evm(format!("err: {message} (supplied gas {gas})"))
    }

    #[tokio::test]
    async fn contract_view_returns_a_value() {
        let (ctx, h, _) = setup(OnMiss::Fetch);
        let out = eth_call(&ctx, call_to(VIEW), &h).await.unwrap();
        assert_eq!(out, CallOutcome::Success(Bytes::from(U256::from(0x2a).to_be_bytes::<32>())));
    }

    #[tokio::test]
    async fn simple_transfer_succeeds_and_sload_reads_state() {
        let (ctx, h, _) = setup(OnMiss::Fetch);
        let mut req = call_to(BOB);
        req.from = Some(ALICE);
        req.value = Some(U256::from(5));
        assert_eq!(eth_call(&ctx, req, &h).await.unwrap(), CallOutcome::Success(Bytes::new()));
        let out = eth_call(&ctx, call_to(SLOADER), &h).await.unwrap();
        assert_eq!(out, CallOutcome::Success(Bytes::from(U256::from(1234).to_be_bytes::<32>())));
    }

    #[tokio::test]
    async fn revert_with_complete_state_is_a_normal_outcome() {
        let (ctx, h, _) = setup(OnMiss::Fetch);
        let out = eth_call(&ctx, call_to(REVERTER), &h).await.unwrap();
        assert_eq!(out, CallOutcome::Revert { data: Bytes::from_static(&[0xde]) });
    }

    #[tokio::test]
    async fn out_of_gas_with_complete_state_is_not_a_miss() {
        let (ctx, h, _) = setup(OnMiss::Fetch);
        let mut req = call_to(SPINNER);
        req.gas = Some(100_000);
        match eth_call(&ctx, req, &h).await {
            Err(CallError::Halted(m)) => assert_eq!(m, "out of gas"),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn error_mode_reports_the_miss_then_error_and_warm_converges() {
        let (ctx, h, honest) = setup(OnMiss::Error);
        let err = eth_call(&ctx, call_to(SLOADER), &h).await.unwrap_err();
        assert!(matches!(err, CallError::Rounds(RoundsError::Missing(n)) if n >= 1), "{err:?}");
        assert_eq!(honest.calls.load(Ordering::SeqCst), 0);
        // Fetch mode completes it.
        let mut fetching = ctx.clone();
        fetching.mode = OnMiss::Fetch;
        assert!(eth_call(&fetching, call_to(SLOADER), &h).await.is_ok());
    }

    #[tokio::test]
    async fn estimate_gas_converges_within_the_error_ratio() {
        let (ctx, h, _) = setup(OnMiss::Fetch);
        // A plain transfer is exactly 21000, and go-pulse adds a fifth.
        let mut req = call_to(BOB);
        req.from = Some(ALICE);
        req.value = Some(U256::from(1));
        assert_eq!(eth_estimate_gas(&ctx, req, &h).await.unwrap(), 25_200);
        // A heavy contract: the search ends within 1.5% of the true minimum.
        let est = eth_estimate_gas(&ctx, call_to(HEAVY), &h).await.unwrap();
        // `est` is `searched + searched / 5`, so this undoes the pad exactly.
        let searched = (est * 5).div_ceil(6);
        let mut at = call_to(HEAVY);
        at.gas = Some(searched);
        assert!(matches!(eth_call(&ctx, at, &h).await, Ok(CallOutcome::Success(_))));
        let mut below = call_to(HEAVY);
        below.gas = Some((searched as f64 * 0.97) as u64);
        assert!(eth_call(&ctx, below, &h).await.is_err(), "est {est} should be near-minimal");
    }

    #[tokio::test]
    async fn the_estimate_follows_geths_search() {
        // geth: lo is the used gas less one, then it tries (peak used + 2300) * 64 / 63, then it
        // bisects with the midpoint capped at 2 * lo until the range is within 1.5%. go-pulse
        // then adds a fifth to the limit the search ends at.
        let (ctx, h, _) = setup(OnMiss::Fetch);
        // VIEW uses 21018 at every limit that suffices; the search ends at 21183.
        assert_eq!(eth_estimate_gas(&ctx, call_to(VIEW), &h).await.unwrap(), 25_419);
        // CLEARER spends 26006 and gets 4800 back, so the 21206 it uses is not enough.
        let at = |gas| TransactionRequest { gas: Some(gas), ..call_to(CLEARER) };
        assert_eq!(
            eth_call(&ctx, at(26_005), &h).await.unwrap_err(),
            CallError::Halted("out of gas".into())
        );
        assert_eq!(
            eth_call(&ctx, at(26_006), &h).await.unwrap(),
            CallOutcome::Success(Bytes::new())
        );
        // The search ends at 26159.
        assert_eq!(eth_estimate_gas(&ctx, call_to(CLEARER), &h).await.unwrap(), 31_390);
        // Only a transfer without data tries 21000 first: one byte costs 16 and starts the search,
        // which ends at 21181.
        let req = TransactionRequest { input: Bytes::from_static(&[1]).into(), ..call_to(BOB) };
        assert_eq!(eth_estimate_gas(&ctx, req, &h).await.unwrap(), 25_417);
    }

    #[tokio::test]
    async fn the_estimate_is_bounded_by_the_block_gas_limit_and_the_allowance() {
        let (ctx, h, _) = setup(OnMiss::Fetch);
        let exceeds = |n: u64| CallError::Halted(format!("gas required exceeds allowance ({n})"));
        // SPINNER never stops, so no limit up to the block's 30M suffices.
        assert_eq!(
            eth_estimate_gas(&ctx, call_to(SPINNER), &h).await.unwrap_err(),
            exceeds(30_000_000)
        );
        // A gas field below a transfer's 21000 is ignored, as in geth.
        let want = eth_estimate_gas(&ctx, call_to(VIEW), &h).await.unwrap();
        for gas in [0, 100] {
            let req = TransactionRequest { gas: Some(gas), ..call_to(VIEW) };
            assert_eq!(eth_estimate_gas(&ctx, req, &h).await.unwrap(), want);
        }
        // ALICE holds 1e18 wei, so at gas price 1e12 she can pay for 1e6 gas.
        let priced = TransactionRequest {
            from: Some(ALICE),
            gas_price: Some(10_u128.pow(12)),
            ..call_to(SPINNER)
        };
        assert_eq!(eth_estimate_gas(&ctx, priced, &h).await.unwrap_err(), exceeds(1_000_000));
        // BOB holds 1 wei: he cannot pay for any gas, nor send more than he holds.
        let broke =
            TransactionRequest { from: Some(BOB), gas_price: Some(1_000), ..call_to(ALICE) };
        assert_eq!(eth_estimate_gas(&ctx, broke.clone(), &h).await.unwrap_err(), exceeds(0));
        // As in geth, a priced call must leave the sender something after the value, which is
        // zero when absent.
        let no_funds = CallError::Evm("insufficient funds for transfer".into());
        for value in [1, 2] {
            let req = TransactionRequest { value: Some(U256::from(value)), ..broke.clone() };
            assert_eq!(eth_estimate_gas(&ctx, req, &h).await.unwrap_err(), no_funds, "{value}");
        }
        let empty = TransactionRequest { from: Some(Address::repeat_byte(0x77)), ..broke };
        assert_eq!(eth_estimate_gas(&ctx, empty, &h).await.unwrap_err(), no_funds);
    }

    #[tokio::test]
    async fn the_pad_is_capped_by_what_the_sender_can_pay() {
        let (ctx, h, _) = setup(OnMiss::Fetch);
        // ALICE holds 1e18 wei, so at 4e13 per gas she can pay for 25000 gas, less than the
        // 25200 a padded transfer asks for.
        let req = TransactionRequest {
            from: Some(ALICE),
            gas_price: Some(4 * 10_u128.pow(13)),
            ..call_to(BOB)
        };
        assert_eq!(eth_estimate_gas(&ctx, req.clone(), &h).await.unwrap(), 25_000);
        // The value is not there to pay for gas: 9e17 wei left pays for 22500.
        let req = TransactionRequest { value: Some(U256::from(10_u64.pow(17))), ..req };
        assert_eq!(eth_estimate_gas(&ctx, req, &h).await.unwrap(), 22_500);
        // A free call has no allowance, so nothing caps the pad.
        let free = TransactionRequest { from: Some(ALICE), ..call_to(BOB) };
        assert_eq!(eth_estimate_gas(&ctx, free, &h).await.unwrap(), 25_200);
    }

    #[tokio::test]
    async fn the_estimate_stops_searching_a_round_with_misses() {
        let (mut ctx, h, honest) = setup(OnMiss::Fetch);
        // Each run reads one block hash, so the hash source counts the runs.
        let runs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = runs.clone();
        ctx.hashes = Arc::new(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            Some(B256::repeat_byte(1))
        });
        // Init code: PUSH1 1 NUMBER SUB BLOCKHASH POP PUSH20 ALICE BALANCE POP STOP
        let code =
            [&[0x60, 1, 0x43, 0x03, 0x40, 0x50, 0x73][..], ALICE.as_slice(), &[0x31, 0x50, 0]]
                .concat();
        let req = TransactionRequest {
            to: Some(TxKind::Create),
            input: Bytes::from(code).into(),
            ..Default::default()
        };
        let est = eth_estimate_gas(&ctx, req.clone(), &h).await.unwrap();
        assert_eq!(honest.calls.load(Ordering::SeqCst), 1);
        // On complete state the same search takes `full` runs, so the round with the miss
        // stopped after its first run.
        let full = runs.swap(0, Ordering::SeqCst) - 1;
        assert_eq!(eth_estimate_gas(&ctx, req, &h).await.unwrap(), est);
        assert_eq!(runs.load(Ordering::SeqCst), full);
        assert!(full > 1, "{full}");
    }

    #[tokio::test]
    async fn a_dropped_estimate_stops_searching_after_its_current_run() {
        use std::sync::atomic::AtomicBool;
        let (mut ctx, h, _) = setup(OnMiss::Fetch);
        // Each run reads one block hash. Once armed, the next read waits until the caller has gone.
        let runs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let started = Arc::new(tokio::sync::Notify::new());
        let released = Arc::new(AtomicBool::new(false));
        let (go, gate) = std::sync::mpsc::channel::<()>();
        let gate = std::sync::Mutex::new(gate);
        let armed = Arc::new(AtomicBool::new(false));
        let (counter, notify, opened, hold) =
            (runs.clone(), started.clone(), released.clone(), armed.clone());
        ctx.hashes = Arc::new(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            if hold.swap(false, Ordering::SeqCst) {
                notify.notify_one();
                let got = gate.lock().unwrap().recv_timeout(Duration::from_secs(30));
                opened.store(got.is_ok(), Ordering::SeqCst);
            }
            Some(B256::repeat_byte(1))
        });
        // Init code that fails with less than 1M gas left, so the search bisects:
        // PUSH1 1 NUMBER SUB BLOCKHASH POP PUSH3 1e6 GAS LT PUSH1 16 JUMPI STOP JUMPDEST INVALID
        const CODE: [u8; 18] = [
            0x60, 1, 0x43, 0x03, 0x40, 0x50, 0x62, 0x0f, 0x42, 0x40, 0x5a, 0x10, 0x60, 16, 0x57, 0,
            0x5b, 0xfe,
        ];
        let req = TransactionRequest {
            to: Some(TxKind::Create),
            input: Bytes::from_static(&CODE).into(),
            ..Default::default()
        };
        // Left to finish, the search takes many runs, and its state is held afterwards.
        eth_estimate_gas(&ctx, req.clone(), &h).await.unwrap();
        assert!(runs.swap(0, Ordering::SeqCst) > 5, "{runs:?}");
        armed.store(true, Ordering::SeqCst);
        {
            let est = eth_estimate_gas(&ctx, req, &h);
            tokio::pin!(est);
            let waited = tokio::time::timeout(Duration::from_secs(30), async {
                tokio::select! {
                    out = &mut est => panic!("the search ended inside its first run: {out:?}"),
                    () = started.notified() => {}
                }
            });
            waited.await.expect("the first run reads a block hash");
        }
        // The caller has gone while its first run waits.
        go.send(()).unwrap();
        // The blocking run gives back its permit when the search returns.
        assert!(permits_free_within(&ctx, Duration::from_secs(30)).await, "the run ends");
        assert!(released.load(Ordering::SeqCst));
        // The run under way when the caller left finishes; no other starts.
        assert_eq!(runs.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn estimate_reports_a_revert() {
        let (ctx, h, _) = setup(OnMiss::Fetch);
        match eth_estimate_gas(&ctx, call_to(REVERTER), &h).await {
            Err(CallError::EstimateReverted(d)) => assert_eq!(d.as_ref(), &[0xde]),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn an_unheld_block_hash_fails_once_state_is_complete() {
        let (ctx, h, honest) = setup(OnMiss::Fetch);
        // Init code: PUSH1 200 NUMBER SUB BLOCKHASH PUSH1 0 MSTORE PUSH1 0x20 PUSH1 0 RETURN
        const CODE: [u8; 13] =
            [0x60, 200, 0x43, 0x03, 0x40, 0x60, 0, 0x52, 0x60, 0x20, 0x60, 0, 0xf3];
        let req = TransactionRequest {
            to: Some(TxKind::Create),
            input: Bytes::from_static(&CODE).into(),
            ..Default::default()
        };
        let want = CallError::Rounds(RoundsError::BlockHashUnavailable(h.number - 200));
        assert_eq!(eth_call(&ctx, req.clone(), &h).await.unwrap_err(), want);
        assert_eq!(eth_estimate_gas(&ctx, req.clone(), &h).await.unwrap_err(), want);
        // The state is held now, so the error modes end on the hash too: not a state miss, and
        // nothing is fetched or queued for it.
        let queue = Arc::new(Queue(std::sync::Mutex::default()));
        let fetches = honest.calls.load(Ordering::SeqCst);
        for mode in [OnMiss::Error, OnMiss::ErrorAndWarm] {
            let mut c = ctx.clone().with_warm(queue.clone());
            c.mode = mode;
            assert_eq!(eth_call(&c, req.clone(), &h).await.unwrap_err(), want, "{mode:?}");
            assert_eq!(eth_estimate_gas(&c, req.clone(), &h).await.unwrap_err(), want, "{mode:?}");
        }
        assert_eq!(honest.calls.load(Ordering::SeqCst), fetches);
        assert!(queue.0.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_priced_estimate_from_an_unheld_sender_is_a_miss_not_a_funds_error() {
        // Until it is fetched, the sender reads as absent, so its zero balance refuses any value.
        let req = TransactionRequest {
            from: Some(ALICE),
            gas_price: Some(1_000),
            value: Some(U256::from(1)),
            ..call_to(BOB)
        };
        for mode in [OnMiss::Error, OnMiss::ErrorAndWarm] {
            let (ctx, h, honest) = setup(mode);
            assert_eq!(
                eth_estimate_gas(&ctx, req.clone(), &h).await.unwrap_err(),
                CallError::Rounds(RoundsError::Missing(1)),
                "{mode:?}"
            );
            assert_eq!(honest.calls.load(Ordering::SeqCst), 0);
            let mut fetching = ctx.clone();
            fetching.mode = OnMiss::Fetch;
            assert_eq!(eth_estimate_gas(&fetching, req.clone(), &h).await.unwrap(), 25_200);
            assert_eq!(eth_estimate_gas(&ctx, req.clone(), &h).await.unwrap(), 25_200, "{mode:?}");
        }
    }

    #[tokio::test]
    async fn the_access_list_is_charged_and_warmed() {
        let (ctx, h, _) = setup(OnMiss::Fetch);
        let list = |entries: Vec<(Address, Vec<B256>)>| {
            Some(AccessList(
                entries
                    .into_iter()
                    .map(|(address, storage_keys)| AccessListItem { address, storage_keys })
                    .collect(),
            ))
        };
        // The least limit that succeeds: `need` does, one less does not.
        let least = async |req: TransactionRequest, need: u64| {
            let at = |gas| TransactionRequest { gas: Some(gas), ..req.clone() };
            assert!(matches!(eth_call(&ctx, at(need), &h).await, Ok(CallOutcome::Success(_))));
            assert!(eth_call(&ctx, at(need - 1), &h).await.is_err(), "{need}");
        };
        // 2400 per address and 1900 per key on top of the 21000 of a transfer.
        let mut req = call_to(BOB);
        req.from = Some(ALICE);
        req.access_list = list(vec![(Address::repeat_byte(0x99), vec![B256::ZERO, B256::ZERO])]);
        let need = 21_000 + 2_400 + 2 * 1_900;
        least(req.clone(), need).await;
        // So 21000 fails, and geth's search over 27200 ends at 27545, padded to 33054.
        assert_eq!(eth_estimate_gas(&ctx, req, &h).await.unwrap(), 33_054);
        // SLOADER runs 18 gas of opcodes and a cold SLOAD of 2100.
        let cold = 21_000 + 18 + 2_100;
        least(call_to(SLOADER), cold).await;
        // A listed slot is warm: its SLOAD costs 100 instead of 2100.
        let mut req = call_to(SLOADER);
        req.access_list = list(vec![(SLOADER, vec![B256::from(U256::from(7))])]);
        least(req, cold + 2_400 + 1_900 - 2_000).await;
    }

    #[tokio::test]
    async fn request_fields_the_node_cannot_honour_are_refused() {
        let (ctx, h, _) = setup(OnMiss::Fetch);
        let mut req = call_to(VIEW);
        req.chain_id = Some(943);
        assert!(eth_call(&ctx, req.clone(), &h).await.is_ok());
        req.chain_id = Some(369);
        let want = CallError::Invalid("chainId does not match node's (have=369, want=943)".into());
        assert_eq!(eth_call(&ctx, req.clone(), &h).await.unwrap_err(), want);
        assert_eq!(eth_estimate_gas(&ctx, req, &h).await.unwrap_err(), want);

        let mut req = call_to(VIEW);
        req.blob_versioned_hashes = Some(vec![B256::ZERO]);
        let want = CallError::Invalid("blobVersionedHashes are not supported".into());
        assert_eq!(eth_call(&ctx, req.clone(), &h).await.unwrap_err(), want);
        assert_eq!(eth_estimate_gas(&ctx, req, &h).await.unwrap_err(), want);

        let mut req = call_to(VIEW);
        req.authorization_list = Some(Vec::new());
        assert!(eth_call(&ctx, req.clone(), &h).await.is_ok(), "an empty list changes nothing");
        req.authorization_list = Some(vec![alloy_eips::eip7702::Authorization {
            chain_id: U256::from(943),
            address: VIEW,
            nonce: 0,
        }
        .into_signed(alloy_primitives::Signature::test_signature())]);
        let want = CallError::Invalid("authorizationList is not supported".into());
        assert_eq!(eth_call(&ctx, req.clone(), &h).await.unwrap_err(), want);
        assert_eq!(eth_estimate_gas(&ctx, req, &h).await.unwrap_err(), want);
    }

    #[tokio::test]
    async fn a_delegation_designator_is_followed_only_under_prague() {
        let (mut ctx, h, _) = setup(OnMiss::Fetch);
        // PulseChain runs Shanghai: the designator is legacy code that starts with 0xEF.
        assert_eq!(
            eth_call(&ctx, call_to(DELEGATED), &h).await.unwrap_err(),
            CallError::Halted("invalid opcode".into())
        );
        ctx.evm = EthEvmConfig::new(reth_chainspec::MAINNET.clone());
        ctx.chain_id = 1;
        let out = eth_call(&ctx, call_to(DELEGATED), &h).await.unwrap();
        assert_eq!(out, CallOutcome::Success(Bytes::from(U256::from(0x2a).to_be_bytes::<32>())));
    }

    /// The BASEFEE, GASPRICE and BALANCE(origin) that `FEE_READER` reports.
    async fn fees_seen(ctx: &ExecCtx, h: &Header, req: TransactionRequest) -> [U256; 3] {
        let Ok(CallOutcome::Success(out)) = eth_call(ctx, req, h).await else { panic!() };
        std::array::from_fn(|i| U256::from_be_slice(&out[i * 32..(i + 1) * 32]))
    }

    #[tokio::test]
    async fn a_priced_call_sees_the_base_fee_and_pays_for_gas() {
        let (ctx, h, _) = setup(OnMiss::Fetch);
        let free = TransactionRequest { from: Some(ALICE), ..call_to(FEE_READER) };
        let alice = U256::from(10_u64.pow(18));
        assert_eq!(fees_seen(&ctx, &h, free.clone()).await, [U256::ZERO, U256::ZERO, alice]);

        // Base fee 1000 and tip 10: the sender pays the gas limit at 1010 before execution.
        let priced = TransactionRequest {
            gas: Some(100_000),
            max_fee_per_gas: Some(2_000),
            max_priority_fee_per_gas: Some(10),
            ..free.clone()
        };
        let paid = alice - U256::from(100_000 * 1_010);
        assert_eq!(fees_seen(&ctx, &h, priced).await, [U256::from(1_000), U256::from(1_010), paid]);
        let legacy = TransactionRequest { gas: Some(100_000), gas_price: Some(1_500), ..free };
        let paid = alice - U256::from(100_000 * 1_500);
        assert_eq!(fees_seen(&ctx, &h, legacy).await, [U256::from(1_000), U256::from(1_500), paid]);

        // BOB holds 1 wei, so he cannot pay for priced gas.
        let broke = TransactionRequest {
            from: Some(BOB),
            gas: Some(100_000),
            gas_price: Some(1_500),
            ..call_to(FEE_READER)
        };
        assert_eq!(
            eth_call(&ctx, broke.clone(), &h).await.unwrap_err(),
            call_err(
                &format!(
                    "insufficient funds for gas * price + value: address {BOB} have 1 want 150000000"
                ),
                100_000
            )
        );
        // The estimate caps the limit at what he can pay, so it fails for lack of gas.
        assert_eq!(
            eth_estimate_gas(&ctx, broke, &h).await.unwrap_err(),
            CallError::Halted("gas required exceeds allowance (0)".into())
        );
    }

    #[test]
    fn gas_price_rules() {
        let mut r = TransactionRequest::default();
        assert_eq!(effective_gas_price(&r, Some(100)).unwrap(), 0);
        r.max_fee_per_gas = Some(150);
        r.max_priority_fee_per_gas = Some(10);
        assert_eq!(effective_gas_price(&r, Some(100)).unwrap(), 110);
        r.max_fee_per_gas = Some(105);
        assert_eq!(effective_gas_price(&r, Some(100)).unwrap(), 105);
        r.gas_price = Some(1);
        assert_eq!(
            effective_gas_price(&r, Some(100)).unwrap_err(),
            CallError::Invalid(
                "both gasPrice and (maxFeePerGas or maxPriorityFeePerGas) specified".into()
            )
        );
        // A missing fee cap is 0, as in geth, so a tip alone is above it.
        let tip_above =
            CallError::Invalid("max priority fee per gas higher than max fee per gas".into());
        for fee_cap in [None, Some(0)] {
            let r = TransactionRequest {
                max_fee_per_gas: fee_cap,
                max_priority_fee_per_gas: Some(5),
                ..Default::default()
            };
            assert_eq!(effective_gas_price(&r, Some(100)).unwrap_err(), tip_above);
        }
    }

    #[tokio::test]
    async fn a_fee_cap_below_the_base_fee_or_the_balance_is_refused() {
        let (ctx, h, _) = setup(OnMiss::Fetch);
        let req = TransactionRequest { from: Some(ALICE), ..call_to(VIEW) };
        let low = TransactionRequest { gas_price: Some(1), ..req.clone() };
        let want = format!(
            "max fee per gas less than block base fee: address {ALICE}, maxFeePerGas: 1, baseFee: 1000"
        );
        assert_eq!(eth_call(&ctx, low.clone(), &h).await.unwrap_err(), call_err(&want, GAS_CAP));
        // geth's estimator wraps the error of its first run with the limit it ran at, the
        // block's 30M here.
        assert_eq!(
            eth_estimate_gas(&ctx, low, &h).await.unwrap_err(),
            CallError::Evm(format!("failed with 30000000 gas: {want}"))
        );
        let low = TransactionRequest { max_fee_per_gas: Some(500), ..req.clone() };
        let want = format!(
            "max fee per gas less than block base fee: address {ALICE}, maxFeePerGas: 500, baseFee: 1000"
        );
        assert_eq!(eth_call(&ctx, low, &h).await.unwrap_err(), call_err(&want, GAS_CAP));

        // The sender must afford the gas limit at the fee cap, not at the price it pays.
        let capped = TransactionRequest {
            gas: Some(100_000),
            max_fee_per_gas: Some(2 * 10_u128.pow(13)),
            max_priority_fee_per_gas: Some(10),
            ..req
        };
        assert_eq!(
            eth_call(&ctx, capped, &h).await.unwrap_err(),
            call_err(
                &format!(
                    "insufficient funds for gas * price + value: address {ALICE} have 1000000000000000000 want 2000000000000000000"
                ),
                100_000
            )
        );
    }

    #[tokio::test]
    async fn evm_errors_carry_geths_messages() {
        let (ctx, h, _) = setup(OnMiss::Fetch);
        let low = TransactionRequest { gas: Some(20_999), ..call_to(BOB) };
        assert_eq!(
            eth_call(&ctx, low, &h).await.unwrap_err(),
            call_err("intrinsic gas too low: have 20999, want 21000", 20_999)
        );

        // A free call skips the balance check, so the transfer itself runs out of funds.
        let overdrawn =
            TransactionRequest { from: Some(BOB), value: Some(U256::from(5)), ..call_to(ALICE) };
        let want =
            format!("insufficient funds for gas * price + value: address {BOB} have 1 want 5");
        assert_eq!(
            eth_call(&ctx, overdrawn.clone(), &h).await.unwrap_err(),
            call_err(&want, GAS_CAP)
        );
        // The estimate drops the error of its 21000 attempt and reports the one at its limit.
        assert_eq!(
            eth_estimate_gas(&ctx, overdrawn, &h).await.unwrap_err(),
            CallError::Evm(format!("failed with 30000000 gas: {want}"))
        );

        for (to, msg) in [(BAD_JUMP, "invalid jump destination"), (UNDERFLOW, "stack underflow")] {
            assert_eq!(
                eth_call(&ctx, call_to(to), &h).await.unwrap_err(),
                CallError::Halted(msg.into())
            );
            assert_eq!(
                eth_estimate_gas(&ctx, call_to(to), &h).await.unwrap_err(),
                CallError::Halted(msg.into())
            );
        }
    }

    #[tokio::test]
    async fn the_error_modes_never_answer_from_missing_state() {
        let (ctx, h, honest) = setup(OnMiss::Error);
        assert!(matches!(
            eth_estimate_gas(&ctx, call_to(SLOADER), &h).await,
            Err(CallError::Rounds(RoundsError::Missing(n))) if n >= 1
        ));
        let queue = Arc::new(Queue(std::sync::Mutex::default()));
        let mut warming = ctx.with_warm(queue.clone());
        warming.mode = OnMiss::ErrorAndWarm;
        let err = eth_call(&warming, call_to(SLOADER), &h).await.unwrap_err();
        let queued = std::mem::take(&mut *queue.0.lock().unwrap());
        assert_eq!(err, CallError::Rounds(RoundsError::Missing(queued.len() as u64)));
        assert!(!queued.is_empty());
        assert_eq!(honest.calls.load(Ordering::SeqCst), 0);
        // Once the warm worker has fetched what was queued, rounds later the call answers.
        for _ in 0..8 {
            let misses = std::mem::take(&mut *queue.0.lock().unwrap());
            honest.fetch(h.state_root, &misses).await.unwrap();
            if let Ok(out) = eth_call(&warming, call_to(SLOADER), &h).await {
                let want = Bytes::from(U256::from(1234).to_be_bytes::<32>());
                assert_eq!(out, CallOutcome::Success(want));
                return;
            }
        }
        panic!("the call never converged");
    }

    #[test]
    fn a_context_exists_only_for_pulsechain() {
        let store: Arc<dyn NodeStore> = Arc::new(Store::in_memory(1 << 10));
        let honest = Arc::new(Honest::new(Arc::new(world(&[])), store.clone()));
        let new = |id| {
            ExecCtx::new(id, store.clone(), Arc::new(|_| None), honest.clone(), OnMiss::Fetch, 4)
        };
        for id in [1, 5, 942, 944] {
            assert!(new(id).is_none(), "{id}");
        }
        for id in [369, 943] {
            let ctx = new(id).unwrap();
            assert_eq!((ctx.chain_id, ctx.evm.chain_spec().chain.id()), (id, id));
        }
    }

    #[tokio::test]
    async fn the_gas_is_clamped_by_the_cap_and_input_wins_over_data() {
        let (mut ctx, h, _) = setup(OnMiss::Fetch);
        ctx.gas_cap = 200_000;
        // Init code: GAS PUSH1 0 MSTORE PUSH1 0x20 PUSH1 0 RETURN
        let gas_left = Bytes::from_static(&[0x5a, 0x60, 0, 0x52, 0x60, 0x20, 0x60, 0, 0xf3]);
        let create = |gas, input: Option<Bytes>, data: Option<Bytes>| TransactionRequest {
            to: Some(TxKind::Create),
            gas,
            input: alloy_rpc_types_eth::TransactionInput { input, data },
            ..Default::default()
        };
        let left = |out: CallOutcome| match out {
            CallOutcome::Success(b) => U256::from_be_slice(&b),
            other => panic!("{other:?}"),
        };
        let at_cap =
            left(eth_call(&ctx, create(None, Some(gas_left.clone()), None), &h).await.unwrap());
        let above = create(Some(10 * ctx.gas_cap), None, Some(gas_left.clone()));
        assert_eq!(left(eth_call(&ctx, above, &h).await.unwrap()), at_cap);
        let below = create(Some(ctx.gas_cap - 1_000), Some(gas_left.clone()), None);
        assert_eq!(left(eth_call(&ctx, below, &h).await.unwrap()), at_cap - U256::from(1_000));
        // With both set, `input` runs: here INVALID, so `data` would have succeeded.
        let both = create(None, Some(Bytes::from_static(&[0xfe])), Some(gas_left));
        assert_eq!(
            eth_call(&ctx, both, &h).await.unwrap_err(),
            CallError::Halted("invalid opcode".into())
        );
    }

    /// Enough gas for SPINNER to loop for minutes.
    const ENDLESS: u64 = 1 << 40;

    /// Waits until every execution permit is free, for at most `within`.
    async fn permits_free_within(ctx: &ExecCtx, within: Duration) -> bool {
        let idle = async {
            while ctx.exec_permits.available_permits() < MAX_CONCURRENT_EXECUTIONS {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        };
        tokio::time::timeout(within, idle).await.is_ok()
    }

    #[tokio::test]
    async fn an_endless_loop_stops_at_the_evm_timeout_and_frees_its_permit() {
        let (mut ctx, mut h, _) = setup(OnMiss::Fetch);
        (ctx.gas_cap, h.gas_limit) = (ENDLESS, ENDLESS);
        ctx.evm_timeout = Duration::from_millis(200);
        let want = CallError::Timeout(Duration::from_millis(200));
        assert_eq!(want.to_string(), "execution aborted (timeout = 200ms)");
        for estimate in [false, true] {
            let started = Instant::now();
            let err = if estimate {
                eth_estimate_gas(&ctx, call_to(SPINNER), &h).await.unwrap_err()
            } else {
                eth_call(&ctx, call_to(SPINNER), &h).await.unwrap_err()
            };
            let took = started.elapsed();
            assert_eq!(err, want, "estimate: {estimate}");
            assert!(took >= ctx.evm_timeout, "estimate: {estimate}, took {took:?}");
            assert!(took < ctx.evm_timeout + Duration::from_secs(1), "took {took:?}");
            assert_eq!(ctx.exec_permits.available_permits(), MAX_CONCURRENT_EXECUTIONS);
        }
    }

    #[tokio::test]
    async fn a_dropped_call_stops_its_run_and_frees_its_permit() {
        let (mut ctx, mut h, _) = setup(OnMiss::Fetch);
        (ctx.gas_cap, h.gas_limit) = (ENDLESS, ENDLESS);
        // No deadline: only the caller going away stops the run.
        ctx.evm_timeout = Duration::ZERO;
        for estimate in [false, true] {
            let run = async {
                if estimate {
                    eth_estimate_gas(&ctx, call_to(SPINNER), &h).await.map(drop)
                } else {
                    eth_call(&ctx, call_to(SPINNER), &h).await.map(drop)
                }
            };
            let gave_up = tokio::time::timeout(Duration::from_millis(100), run).await;
            assert!(gave_up.is_err(), "estimate: {estimate}: {gave_up:?}");
            assert!(
                permits_free_within(&ctx, Duration::from_secs(1)).await,
                "estimate: {estimate}: the run went on after its caller left"
            );
        }
    }

    #[tokio::test]
    async fn a_zero_evm_timeout_sets_no_deadline() {
        let (mut ctx, mut h, _) = setup(OnMiss::Fetch);
        // Long enough to pass 1 ms, short enough to run out of gas in a test.
        let gas = 50_000_000;
        (ctx.gas_cap, h.gas_limit) = (gas, gas);
        ctx.evm_timeout = Duration::from_millis(1);
        let want = CallError::Timeout(Duration::from_millis(1));
        assert_eq!(eth_call(&ctx, call_to(SPINNER), &h).await.unwrap_err(), want);
        ctx.evm_timeout = Duration::ZERO;
        let err = eth_call(&ctx, call_to(SPINNER), &h).await.unwrap_err();
        assert_eq!(err, CallError::Halted("out of gas".into()));
    }

    #[tokio::test]
    async fn a_normal_call_finishes_under_the_default_evm_timeout() {
        let (ctx, h, _) = setup(OnMiss::Fetch);
        assert_eq!(ctx.evm_timeout, DEFAULT_EVM_TIMEOUT);
        assert_eq!(DEFAULT_EVM_TIMEOUT, Duration::from_secs(5));
        let out = eth_call(&ctx, call_to(SLOADER), &h).await.unwrap();
        assert_eq!(out, CallOutcome::Success(Bytes::from(U256::from(1234).to_be_bytes::<32>())));
        assert_eq!(eth_estimate_gas(&ctx, call_to(VIEW), &h).await.unwrap(), 25_419);
    }

    /// The texts Go's `time.Duration.String` gives, which geth prints in its timeout error.
    #[test]
    fn durations_print_as_go_prints_them() {
        for (d, want) in [
            (Duration::ZERO, "0s"),
            (Duration::from_nanos(1), "1ns"),
            (Duration::from_nanos(1_500), "1.5µs"),
            (Duration::from_micros(1_500), "1.5ms"),
            (Duration::from_millis(250), "250ms"),
            (Duration::from_secs(1), "1s"),
            (Duration::from_millis(1_500), "1.5s"),
            (Duration::from_secs(5), "5s"),
            (Duration::from_nanos(5_000_000_001), "5.000000001s"),
            (Duration::from_secs(60), "1m0s"),
            (Duration::from_secs(90), "1m30s"),
            (Duration::from_secs(3_600), "1h0m0s"),
            (Duration::from_millis(5_400_500), "1h30m0.5s"),
            (Duration::from_secs(86_400), "24h0m0s"),
        ] {
            assert_eq!(go_duration(d), want, "{d:?}");
        }
    }

    mod props {
        use super::*;
        use proptest::prelude::*;

        fn fee() -> impl Strategy<Value = Option<u128>> {
            prop_oneof![
                Just(None),
                Just(Some(0)),
                any::<u128>().prop_map(Some),
                (0u128..5_000).prop_map(Some)
            ]
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            /// The price follows geth: `gasPrice` as given, else the tip plus the base fee capped
            /// by the fee cap, and a missing 1559 field is zero.
            #[test]
            fn the_effective_gas_price_follows_geth(
                gas_price in fee(),
                fee_cap in fee(),
                tip in fee(),
                base_fee in prop_oneof![Just(None), any::<u64>().prop_map(Some), (0u64..5_000).prop_map(Some)],
            ) {
                let req = TransactionRequest {
                    gas_price,
                    max_fee_per_gas: fee_cap,
                    max_priority_fee_per_gas: tip,
                    ..Default::default()
                };
                let got = effective_gas_price(&req, base_fee);
                let has_1559 = fee_cap.is_some() || tip.is_some();
                let (cap, tip) = (fee_cap.unwrap_or(0), tip.unwrap_or(0));
                match (gas_price, has_1559) {
                    (Some(_), true) => prop_assert!(matches!(got, Err(CallError::Invalid(_)))),
                    (Some(p), false) => prop_assert_eq!(got, Ok(p)),
                    (None, _) if cap == 0 && tip == 0 => prop_assert_eq!(got, Ok(0)),
                    (None, _) if tip > cap => prop_assert!(matches!(got, Err(CallError::Invalid(_)))),
                    (None, _) => {
                        // The code saturates, so an overflowing sum is the fee cap.
                        let want = tip
                            .checked_add(u128::from(base_fee.unwrap_or(0)))
                            .map_or(cap, |p| p.min(cap));
                        prop_assert_eq!(got, Ok(want));
                    }
                }
            }
        }
    }
}
