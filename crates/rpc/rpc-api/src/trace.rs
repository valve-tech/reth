use alloy_eips::BlockId;
use alloy_primitives::{map::HashSet, Bytes, B256};
use alloy_rpc_types_eth::{state::StateOverride, BlockOverrides, Index};
use alloy_rpc_types_trace::{
    filter::TraceFilter,
    opcode::{BlockOpcodeGas, TransactionOpcodeGas},
    parity::*,
};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use serde::{ser::SerializeStruct, Deserialize, Serialize, Serializer};

/// Ethereum trace API
#[cfg_attr(not(feature = "client"), rpc(server, namespace = "trace"))]
#[cfg_attr(feature = "client", rpc(server, client, namespace = "trace"))]
pub trait TraceApi<TxReq> {
    /// Executes the given call and returns a number of possible traces for it.
    #[method(name = "call")]
    async fn trace_call(
        &self,
        call: TxReq,
        trace_types: HashSet<TraceType>,
        block_id: Option<BlockId>,
        state_overrides: Option<StateOverride>,
        block_overrides: Option<Box<BlockOverrides>>,
    ) -> RpcResult<TraceResults>;

    /// Performs multiple call traces on top of the same block, defaulting to latest when no block
    /// is specified. Each call is executed with the preceding calls applied first, allowing
    /// dependent transactions to be traced.
    #[method(name = "callMany")]
    async fn trace_call_many(
        &self,
        calls: Vec<(TxReq, HashSet<TraceType>)>,
        block_id: Option<BlockId>,
    ) -> RpcResult<Vec<TraceResults>>;

    /// Traces a call to `eth_sendRawTransaction` without making the call, returning the traces.
    ///
    /// Expects a raw transaction data
    #[method(name = "rawTransaction")]
    async fn trace_raw_transaction(
        &self,
        data: Bytes,
        trace_types: HashSet<TraceType>,
        block_id: Option<BlockId>,
    ) -> RpcResult<TraceResults>;

    /// Replays all transactions in a block returning the requested traces for each transaction.
    #[method(name = "replayBlockTransactions")]
    async fn replay_block_transactions(
        &self,
        block_id: BlockId,
        trace_types: HashSet<TraceType>,
    ) -> RpcResult<Option<Vec<TraceResultsWithTransactionHash>>>;

    /// Replays a transaction, returning the traces or `None` if the transaction does not exist.
    #[method(name = "replayTransaction")]
    async fn replay_transaction(
        &self,
        transaction: B256,
        trace_types: HashSet<TraceType>,
    ) -> RpcResult<Option<TraceResultsWithTransactionHash>>;

    /// Returns traces created at given block.
    #[method(name = "block")]
    async fn trace_block(&self, block_id: BlockId) -> RpcResult<Option<Vec<ParityLocalizedTrace>>>;

    /// Returns traces matching given filter.
    ///
    /// This is similar to `eth_getLogs` but for traces. Omitted range bounds default to latest.
    #[method(name = "filter")]
    async fn trace_filter(&self, filter: TraceFilter) -> RpcResult<Vec<ParityLocalizedTrace>>;

    /// Returns the transaction trace at the given `traceAddress` path.
    ///
    /// An empty path selects the root, `[0]` selects its first child, and `[0, 1]` selects that
    /// child's second child. Returns `None` if the transaction or path does not exist.
    /// Callers requiring a flat index can index the result of `trace_transaction` instead.
    #[method(name = "get")]
    async fn trace_get(
        &self,
        hash: B256,
        indices: Vec<Index>,
    ) -> RpcResult<Option<ParityLocalizedTrace>>;

    /// Returns all traces of given transaction.
    #[method(name = "transaction")]
    async fn trace_transaction(&self, hash: B256) -> RpcResult<Option<Vec<ParityLocalizedTrace>>>;

    /// Returns all opcodes with their count and combined gas usage for the given transaction in no
    /// particular order.
    #[method(name = "transactionOpcodeGas")]
    async fn trace_transaction_opcode_gas(
        &self,
        tx_hash: B256,
    ) -> RpcResult<Option<TransactionOpcodeGas>>;

    /// Returns the opcodes of all transactions in the given block.
    ///
    /// This is the same as `trace_transactionOpcodeGas` but for all transactions in a block.
    #[method(name = "blockOpcodeGas")]
    async fn trace_block_opcode_gas(&self, block_id: BlockId) -> RpcResult<Option<BlockOpcodeGas>>;
}

/// A [`LocalizedTransactionTrace`] in the wire shape of erigon and reth v2.6.0.
///
/// Alloy 2.5.0 writes `transactionHash` and `transactionPosition` as `null` when they are absent,
/// for example on reward traces. Erigon omits both keys, and Pulsechain clients hash the response
/// bytes, so this type omits them too. All other fields keep alloy's order and encoding.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct ParityLocalizedTrace(pub LocalizedTransactionTrace);

impl Serialize for ParityLocalizedTrace {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let LocalizedTransactionTrace {
            trace,
            block_hash,
            block_number,
            transaction_hash,
            transaction_position,
        } = &self.0;
        let TransactionTrace { action, error, result, subtraces, trace_address } = trace;

        let mut s = serializer.serialize_struct("LocalizedTransactionTrace", 9)?;
        match action {
            Action::Call(action) => s.serialize_field("action", action)?,
            Action::Create(action) => s.serialize_field("action", action)?,
            Action::Selfdestruct(action) => s.serialize_field("action", action)?,
            Action::Reward(action) => s.serialize_field("action", action)?,
        }
        if let Some(block_hash) = block_hash {
            s.serialize_field("blockHash", block_hash)?;
        }
        if let Some(block_number) = block_number {
            s.serialize_field("blockNumber", block_number)?;
        }
        if let Some(error) = error {
            s.serialize_field("error", error)?;
        }
        match result {
            Some(TraceOutput::Call(call)) => s.serialize_field("result", call)?,
            Some(TraceOutput::Create(create)) => s.serialize_field("result", create)?,
            None => s.serialize_field("result", &None::<()>)?,
        }
        s.serialize_field("subtraces", subtraces)?;
        s.serialize_field("traceAddress", trace_address)?;
        if let Some(transaction_hash) = transaction_hash {
            s.serialize_field("transactionHash", transaction_hash)?;
        }
        if let Some(transaction_position) = transaction_position {
            s.serialize_field("transactionPosition", transaction_position)?;
        }
        s.serialize_field("type", &action.kind())?;
        s.end()
    }
}

impl From<LocalizedTransactionTrace> for ParityLocalizedTrace {
    fn from(trace: LocalizedTransactionTrace) -> Self {
        Self(trace)
    }
}

impl From<ParityLocalizedTrace> for LocalizedTransactionTrace {
    fn from(trace: ParityLocalizedTrace) -> Self {
        trace.0
    }
}

impl core::ops::Deref for ParityLocalizedTrace {
    type Target = LocalizedTransactionTrace;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, b256, Address, U256};

    fn reward(
        block_hash: B256,
        block_number: u64,
        author: Address,
        value: U256,
    ) -> ParityLocalizedTrace {
        ParityLocalizedTrace(LocalizedTransactionTrace {
            trace: TransactionTrace {
                action: Action::Reward(RewardAction {
                    author,
                    reward_type: RewardType::Block,
                    value,
                }),
                error: None,
                result: None,
                subtraces: 0,
                trace_address: vec![],
            },
            block_hash: Some(block_hash),
            block_number: Some(block_number),
            transaction_hash: None,
            transaction_position: None,
        })
    }

    /// Pulsechain testnet (943) block 0xc26af0, trace index 823, as erigon and reth v2.6.0 return
    /// it. The digest `4d407d1c9e51` that identified this trace uses an unknown hash scheme, so the
    /// test pins the exact bytes instead.
    #[test]
    fn pulsechain_943_reward_trace_bytes() {
        let trace = reward(
            b256!("0xd8e9e0de59516123c400e521a2be72debd99cd0e4c23a906ce29b77f7a62e831"),
            0xc26af0,
            address!("0x1ad91ee08f21be3de0ba2ba6918e714da6b45836"),
            U256::from(0x1bc16d674ec80000u64),
        );
        let expected = r#"{"action":{"author":"0x1ad91ee08f21be3de0ba2ba6918e714da6b45836","rewardType":"block","value":"0x1bc16d674ec80000"},"blockHash":"0xd8e9e0de59516123c400e521a2be72debd99cd0e4c23a906ce29b77f7a62e831","blockNumber":12741360,"result":null,"subtraces":0,"traceAddress":[],"type":"reward"}"#;
        assert_eq!(serde_json::to_string(&trace).unwrap(), expected);
        assert_eq!(serde_json::from_str::<ParityLocalizedTrace>(expected).unwrap(), trace);
    }

    #[test]
    fn transaction_trace_bytes() {
        let trace = ParityLocalizedTrace(LocalizedTransactionTrace {
            trace: TransactionTrace {
                action: Action::Call(CallAction {
                    from: Address::with_last_byte(1),
                    to: Address::with_last_byte(2),
                    gas: 0x5208,
                    call_type: CallType::Call,
                    ..Default::default()
                }),
                error: Some("Reverted".into()),
                result: None,
                subtraces: 1,
                trace_address: vec![0],
            },
            block_hash: Some(B256::with_last_byte(3)),
            block_number: Some(7),
            transaction_hash: Some(B256::with_last_byte(4)),
            transaction_position: Some(5),
        });
        let expected = r#"{"action":{"from":"0x0000000000000000000000000000000000000001","callType":"call","gas":"0x5208","input":"0x","to":"0x0000000000000000000000000000000000000002","value":"0x0"},"blockHash":"0x0000000000000000000000000000000000000000000000000000000000000003","blockNumber":7,"error":"Reverted","result":null,"subtraces":1,"traceAddress":[0],"transactionHash":"0x0000000000000000000000000000000000000000000000000000000000000004","transactionPosition":5,"type":"call"}"#;
        let json = serde_json::to_string(&trace).unwrap();
        assert_eq!(json, expected);
        // With every optional field set, the shape must equal alloy's own serializer.
        assert_eq!(json, serde_json::to_string(&trace.0).unwrap());
    }

    #[test]
    fn pending_trace_omits_absent_fields() {
        let mut trace = reward(B256::ZERO, 0, Address::ZERO, U256::ZERO).0;
        trace.block_hash = None;
        trace.block_number = None;
        trace.transaction_position = Some(0);
        let json = serde_json::to_string(&ParityLocalizedTrace(trace)).unwrap();
        assert_eq!(
            json,
            r#"{"action":{"author":"0x0000000000000000000000000000000000000000","rewardType":"block","value":"0x0"},"result":null,"subtraces":0,"traceAddress":[],"transactionPosition":0,"type":"reward"}"#
        );
    }
}
