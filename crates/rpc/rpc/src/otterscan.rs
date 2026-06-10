use alloy_consensus::{constants::KECCAK_EMPTY, BlockHeader, Typed2718};
use alloy_eips::{eip1898::LenientBlockNumberOrTag, BlockId, BlockNumberOrTag};
use alloy_network::{ReceiptResponse, TransactionResponse};
use alloy_primitives::{Address, Bloom, Bytes, TxHash, B256, U256};
use alloy_rpc_types_eth::{BlockTransactions, TransactionReceipt};
use alloy_rpc_types_trace::{
    filter::{TraceFilter, TraceFilterMatcher, TraceFilterMode},
    otterscan::{
        BlockDetails, ContractCreator, InternalOperation, OperationType, OtsBlockTransactions,
        OtsReceipt, OtsTransactionReceipt, TraceEntry, TransactionsWithReceipts,
    },
    parity::{Action, CreateAction, CreateOutput, TraceOutput},
};
use async_trait::async_trait;
use futures::{stream, StreamExt};
use jsonrpsee::{core::RpcResult, types::ErrorObjectOwned};
use reth_primitives_traits::{RecoveredBlock, TxTy};
use reth_rpc_api::{EthApiServer, OtterscanServer};
use reth_rpc_convert::RpcTxReq;
use reth_rpc_eth_api::{
    helpers::{EthTransactions, TraceExt},
    FullEthApiTypes, RpcBlock, RpcHeader, RpcReceipt, RpcTransaction,
};
use reth_rpc_eth_types::{utils::binary_search, EthApiError};
use reth_rpc_server_types::result::internal_rpc_err;
use reth_storage_api::{AccountHistoryReader, BlockReader, ProviderBlock};
use revm::context_interface::result::ExecutionResult;
use revm_inspectors::{
    tracing::{types::CallTraceNode, TracingInspectorConfig},
    transfer::{TransferInspector, TransferKind},
};
use revm_primitives::FixedBytes;
use std::{cmp::Reverse, sync::Arc};

const API_LEVEL: u64 = 8;

/// Number of candidate blocks fetched from the account-history index per batch during
/// `ots_searchTransactions{Before,After}`.
const CANDIDATE_BATCH_SIZE: usize = 64;

/// Maximum number of blocks traced concurrently during `ots_searchTransactions{Before,After}`.
const MAX_CONCURRENT_BLOCK_TRACES: usize = 8;

/// Otterscan API.
#[derive(Debug)]
pub struct OtterscanApi<Eth> {
    eth: Eth,
}

impl<Eth> OtterscanApi<Eth> {
    /// Creates a new instance of `Otterscan`.
    pub const fn new(eth: Eth) -> Self {
        Self { eth }
    }
}

impl<Eth> OtterscanApi<Eth>
where
    Eth: FullEthApiTypes,
{
    /// Constructs a `BlockDetails` from a block and its receipts.
    fn block_details(
        &self,
        block: RpcBlock<Eth::NetworkTypes>,
        receipts: Vec<RpcReceipt<Eth::NetworkTypes>>,
    ) -> RpcResult<BlockDetails<RpcHeader<Eth::NetworkTypes>>> {
        // blob fee is burnt, so we don't need to calculate it
        let total_fees = receipts
            .iter()
            .map(|receipt| {
                (receipt.gas_used() as u128).saturating_mul(receipt.effective_gas_price())
            })
            .sum::<u128>();

        Ok(BlockDetails::new(block, Default::default(), U256::from(total_fees)))
    }
}

impl<Eth> OtterscanApi<Eth>
where
    Eth: EthApiServer<
            RpcTxReq<Eth::NetworkTypes>,
            RpcTransaction<Eth::NetworkTypes>,
            RpcBlock<Eth::NetworkTypes>,
            RpcReceipt<Eth::NetworkTypes>,
            RpcHeader<Eth::NetworkTypes>,
            TxTy<Eth::Primitives>,
        > + EthTransactions
        + TraceExt
        + 'static,
{
    /// Fetches the recovered blocks for the given block numbers.
    fn recovered_blocks(
        &self,
        numbers: &[u64],
    ) -> RpcResult<Vec<Arc<RecoveredBlock<ProviderBlock<Eth::Provider>>>>> {
        let mut blocks = Vec::with_capacity(numbers.len());
        for &number in numbers {
            blocks.extend(
                self.eth
                    .provider()
                    .recovered_block_range(number..=number)
                    .map_err(|_| EthApiError::HeaderRangeNotFound(number.into(), number.into()))?
                    .into_iter()
                    .map(Arc::new),
            );
        }
        Ok(blocks)
    }

    /// Traces the given blocks with a parity tracing inspector and appends the transactions
    /// (and their receipts) whose traces match `matcher` to `out`.
    ///
    /// At most [`MAX_CONCURRENT_BLOCK_TRACES`] blocks are traced concurrently.
    async fn collect_matching_transactions(
        &self,
        blocks: Vec<Arc<RecoveredBlock<ProviderBlock<Eth::Provider>>>>,
        matcher: &Arc<TraceFilterMatcher>,
        out: &mut TransactionsWithReceipts<RpcTransaction<Eth::NetworkTypes>>,
    ) -> RpcResult<()> {
        let mut block_timestamps = std::collections::HashMap::new();
        let mut futures = Vec::with_capacity(blocks.len());

        for block in &blocks {
            let matcher = matcher.clone();
            block_timestamps.insert(block.hash(), block.header().timestamp());

            futures.push(self.eth.trace_block_until(
                block.hash().into(),
                Some(block.clone()),
                None,
                TracingInspectorConfig::default_parity(),
                move |tx_info, mut ctx| {
                    let mut traces = ctx
                        .take_inspector()
                        .into_parity_builder()
                        .into_localized_transaction_traces(tx_info);
                    traces.retain(|trace| matcher.matches(&trace.trace));

                    Ok(Some(traces))
                },
            ));
        }

        // execute the traces with bounded concurrency
        let mut results = stream::iter(futures).buffer_unordered(MAX_CONCURRENT_BLOCK_TRACES);

        while let Some(result) = results.next().await {
            let traces = result
                .map_err(Into::into)?
                .into_iter()
                .flatten()
                .flat_map(|traces| traces.into_iter().flatten())
                .collect::<Vec<_>>();

            let mut prev_tx_hash = FixedBytes::default();

            // iterate over the traces and fetch the corresponding transactions and receipts
            for trace in &traces {
                let tx_hash = trace.transaction_hash.ok_or(EthApiError::TransactionNotFound)?;

                // If intermediate traces of the same transaction are matched, skip them
                if tx_hash == prev_tx_hash {
                    continue;
                }
                prev_tx_hash = tx_hash;

                let tx = EthApiServer::transaction_by_hash(&self.eth, tx_hash);
                let receipt = EthApiServer::transaction_receipt(&self.eth, tx_hash);
                let (tx, receipt) = futures::try_join!(tx, receipt)?;
                let tx = tx.ok_or(EthApiError::TransactionNotFound)?;
                let receipt = receipt.ok_or(EthApiError::ReceiptNotFound)?;

                let inner = OtsReceipt {
                    status: receipt.status(),
                    cumulative_gas_used: receipt.cumulative_gas_used(),
                    logs: Some(vec![]),
                    logs_bloom: Some(Bloom::default()),
                    r#type: tx.ty(),
                };

                let receipt = TransactionReceipt {
                    inner,
                    transaction_hash: receipt.transaction_hash(),
                    transaction_index: receipt.transaction_index(),
                    block_hash: receipt.block_hash(),
                    block_number: receipt.block_number(),
                    gas_used: receipt.gas_used(),
                    effective_gas_price: receipt.effective_gas_price(),
                    blob_gas_used: receipt.blob_gas_used(),
                    blob_gas_price: receipt.blob_gas_price(),
                    from: receipt.from(),
                    to: receipt.to(),
                    contract_address: receipt.contract_address(),
                };

                let receipt = OtsTransactionReceipt {
                    receipt,
                    timestamp: trace
                        .block_hash
                        .and_then(|hash| block_timestamps.get(&hash).copied()),
                };

                out.txs.push(tx);
                out.receipts.push(receipt);
            }
        }

        Ok(())
    }

    /// Exhaustive fallback for `ots_searchTransactionsBefore`, used when the account-history
    /// index is unusable (e.g. account history is pruned): linearly walks all blocks from
    /// `cur_block` down to genesis, tracing every block. This is the pre-index implementation
    /// and can be extremely slow on long chains.
    async fn search_transactions_before_linear(
        &self,
        matcher: &Arc<TraceFilterMatcher>,
        out: &mut TransactionsWithReceipts<RpcTransaction<Eth::NetworkTypes>>,
        mut cur_block: u64,
        page_size: usize,
    ) -> RpcResult<()> {
        const BATCH_SIZE: u64 = 1000;

        // iterate over the blocks until `page_size` transactions are found or the genesis block
        // is reached
        while out.txs.len() < page_size {
            let start = cur_block.saturating_sub(BATCH_SIZE);
            let end = cur_block;

            let blocks = self
                .eth
                .provider()
                .recovered_block_range(start..=end)
                .map_err(|_| EthApiError::HeaderRangeNotFound(start.into(), end.into()))?
                .into_iter()
                .map(Arc::new)
                .collect::<Vec<_>>();

            self.collect_matching_transactions(blocks, matcher, out).await?;

            if start == 0 {
                // Genesis block is reached meaning this is the last page of the transactions
                out.last_page = true;
                break;
            }

            cur_block = start - 1;
        }

        Ok(())
    }

    /// Exhaustive fallback for `ots_searchTransactionsAfter`, used when the account-history
    /// index is unusable (e.g. account history is pruned): linearly walks all blocks from
    /// `cur_block` up to the tip, tracing every block. This is the pre-index implementation and
    /// can be extremely slow on long chains.
    async fn search_transactions_after_linear(
        &self,
        matcher: &Arc<TraceFilterMatcher>,
        out: &mut TransactionsWithReceipts<RpcTransaction<Eth::NetworkTypes>>,
        mut cur_block: u64,
        tip: u64,
        page_size: usize,
    ) -> RpcResult<()> {
        const BATCH_SIZE: u64 = 1000;

        // iterate over the blocks until `page_size` transactions are found or the tip is reached
        while out.txs.len() < page_size {
            let start = cur_block;
            let end = std::cmp::min(tip, cur_block + BATCH_SIZE);

            let blocks = self
                .eth
                .provider()
                .recovered_block_range(start..=end)
                .map_err(|_| EthApiError::HeaderRangeNotFound(start.into(), end.into()))?
                .into_iter()
                .map(Arc::new)
                .collect::<Vec<_>>();

            self.collect_matching_transactions(blocks, matcher, out).await?;

            if end == tip {
                // most current block is reached meaning this is the first page of the
                // transactions
                out.first_page = true;
                break;
            }

            cur_block = end + 1;
        }

        Ok(())
    }
}

#[async_trait]
impl<Eth> OtterscanServer<RpcTransaction<Eth::NetworkTypes>, RpcHeader<Eth::NetworkTypes>>
    for OtterscanApi<Eth>
where
    Eth: EthApiServer<
            RpcTxReq<Eth::NetworkTypes>,
            RpcTransaction<Eth::NetworkTypes>,
            RpcBlock<Eth::NetworkTypes>,
            RpcReceipt<Eth::NetworkTypes>,
            RpcHeader<Eth::NetworkTypes>,
            TxTy<Eth::Primitives>,
        > + EthTransactions
        + TraceExt
        + 'static,
{
    /// Handler for `ots_getHeaderByNumber` and `erigon_getHeaderByNumber`
    async fn get_header_by_number(
        &self,
        block_number: LenientBlockNumberOrTag,
    ) -> RpcResult<Option<RpcHeader<Eth::NetworkTypes>>> {
        self.eth.header_by_number(block_number.into()).await
    }

    /// Handler for `ots_hasCode`
    async fn has_code(&self, address: Address, block_id: Option<BlockId>) -> RpcResult<bool> {
        EthApiServer::get_code(&self.eth, address, block_id).await.map(|code| !code.is_empty())
    }

    /// Handler for `ots_getApiLevel`
    async fn get_api_level(&self) -> RpcResult<u64> {
        Ok(API_LEVEL)
    }

    /// Handler for `ots_getInternalOperations`
    async fn get_internal_operations(&self, tx_hash: TxHash) -> RpcResult<Vec<InternalOperation>> {
        let internal_operations = self
            .eth
            .spawn_trace_transaction_in_block_with_inspector(
                tx_hash,
                TransferInspector::new(false),
                |_tx_info, inspector, _, _| Ok(inspector.into_transfers()),
            )
            .await
            .map_err(Into::into)?
            .map(|transfer_operations| {
                transfer_operations
                    .iter()
                    .map(|op| InternalOperation {
                        from: op.from,
                        to: op.to,
                        value: op.value,
                        r#type: match op.kind {
                            TransferKind::Call => OperationType::OpTransfer,
                            TransferKind::Create => OperationType::OpCreate,
                            TransferKind::Create2 => OperationType::OpCreate2,
                            TransferKind::SelfDestruct => OperationType::OpSelfDestruct,
                        },
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        Ok(internal_operations)
    }

    /// Handler for `ots_getTransactionError`
    async fn get_transaction_error(&self, tx_hash: TxHash) -> RpcResult<Option<Bytes>> {
        let maybe_revert = self
            .eth
            .spawn_replay_transaction(tx_hash, |_tx_info, res, _| match res.result {
                ExecutionResult::Revert { output, .. } => Ok(Some(output)),
                _ => Ok(None),
            })
            .await
            .map(Option::flatten)
            .map_err(Into::into)?;
        Ok(maybe_revert)
    }

    /// Handler for `ots_traceTransaction`
    async fn trace_transaction(&self, tx_hash: TxHash) -> RpcResult<Option<Vec<TraceEntry>>> {
        let traces = self
            .eth
            .spawn_trace_transaction_in_block(
                tx_hash,
                TracingInspectorConfig::default_parity(),
                move |_tx_info, inspector, _, _| Ok(inspector.into_traces().into_nodes()),
            )
            .await
            .map_err(Into::into)?
            .map(|traces| {
                traces
                    .into_iter()
                    .map(|CallTraceNode { trace, .. }| TraceEntry {
                        r#type: if trace.is_selfdestruct() {
                            "SELFDESTRUCT".to_string()
                        } else {
                            trace.kind.to_string()
                        },
                        depth: trace.depth as u32,
                        from: trace.caller,
                        to: trace.address,
                        value: Some(trace.value),
                        input: trace.data,
                        output: trace.output,
                    })
                    .collect::<Vec<_>>()
            });
        Ok(traces)
    }

    /// Handler for `ots_getBlockDetails`
    async fn get_block_details(
        &self,
        block_number: LenientBlockNumberOrTag,
    ) -> RpcResult<BlockDetails<RpcHeader<Eth::NetworkTypes>>> {
        let block_number = block_number.into_inner();
        let block = self.eth.block_by_number(block_number, true);
        let block_id = block_number.into();
        let receipts = self.eth.block_receipts(block_id);
        let (block, receipts) = futures::try_join!(block, receipts)?;
        self.block_details(
            block.ok_or(EthApiError::HeaderNotFound(block_id))?,
            receipts.ok_or(EthApiError::ReceiptsNotFound(block_id))?,
        )
    }

    /// Handler for `ots_getBlockDetailsByHash`
    async fn get_block_details_by_hash(
        &self,
        block_hash: B256,
    ) -> RpcResult<BlockDetails<RpcHeader<Eth::NetworkTypes>>> {
        let block = self.eth.block_by_hash(block_hash, true);
        let block_id = block_hash.into();
        let receipts = self.eth.block_receipts(block_id);
        let (block, receipts) = futures::try_join!(block, receipts)?;
        self.block_details(
            block.ok_or(EthApiError::HeaderNotFound(block_id))?,
            receipts.ok_or(EthApiError::ReceiptsNotFound(block_id))?,
        )
    }

    /// Handler for `ots_getBlockTransactions`
    async fn get_block_transactions(
        &self,
        block_number: LenientBlockNumberOrTag,
        page_number: usize,
        page_size: usize,
    ) -> RpcResult<
        OtsBlockTransactions<RpcTransaction<Eth::NetworkTypes>, RpcHeader<Eth::NetworkTypes>>,
    > {
        let block_number = block_number.into_inner();
        // retrieve full block and its receipts
        let block = self.eth.block_by_number(block_number, true);
        let block_id = block_number.into();
        let receipts = self.eth.block_receipts(block_id);
        let (block, receipts) = futures::try_join!(block, receipts)?;

        let mut block = block.ok_or(EthApiError::HeaderNotFound(block_id))?;
        let mut receipts = receipts.ok_or(EthApiError::ReceiptsNotFound(block_id))?;

        // check if the number of transactions matches the number of receipts
        let tx_len = block.transactions.len();
        if tx_len != receipts.len() {
            return Err(internal_rpc_err(
                "the number of transactions does not match the number of receipts",
            ))
        }

        // make sure the block is full
        let BlockTransactions::Full(transactions) = &mut block.transactions else {
            return Err(internal_rpc_err("block is not full"));
        };

        let page = block_transaction_page_range(tx_len, page_number, page_size);

        // Crop transactions
        *transactions = transactions.drain(page.clone()).collect::<Vec<_>>();

        // Crop receipts and transform them into OtsTransactionReceipt
        let timestamp = Some(block.header.timestamp());
        let receipts = receipts
            .drain(page)
            .zip(transactions.iter().map(Typed2718::ty))
            .map(|(receipt, tx_ty)| {
                let inner = OtsReceipt {
                    status: receipt.status(),
                    cumulative_gas_used: receipt.cumulative_gas_used(),
                    logs: None,
                    logs_bloom: None,
                    r#type: tx_ty,
                };

                let receipt = TransactionReceipt {
                    inner,
                    transaction_hash: receipt.transaction_hash(),
                    transaction_index: receipt.transaction_index(),
                    block_hash: receipt.block_hash(),
                    block_number: receipt.block_number(),
                    gas_used: receipt.gas_used(),
                    effective_gas_price: receipt.effective_gas_price(),
                    blob_gas_used: receipt.blob_gas_used(),
                    blob_gas_price: receipt.blob_gas_price(),
                    from: receipt.from(),
                    to: receipt.to(),
                    contract_address: receipt.contract_address(),
                };

                OtsTransactionReceipt { receipt, timestamp }
            })
            .collect();

        // use `transaction_count` to indicate the paginate information
        let mut block = OtsBlockTransactions { fullblock: block.into(), receipts };
        block.fullblock.transaction_count = tx_len;
        Ok(block)
    }

    /// Handler for `ots_searchTransactionsBefore`
    ///
    /// For EOAs, candidate blocks are selected via the account-history index (see
    /// [`AccountHistoryReader`]) instead of linearly re-executing every block of the chain. An
    /// EOA's state-change history is effectively complete: any value transfer or outgoing
    /// transaction changes its balance and/or nonce. The only misses are zero-value incoming
    /// `CALL`s and reverted incoming calls (which Erigon's call index would list) — a deliberate
    /// trade for bounded query cost. If the account-history index is unusable (e.g. account
    /// history is pruned), the EOA path falls back to the exhaustive linear scan.
    ///
    /// Contracts intentionally keep the exhaustive trace-based linear scan
    /// ([`Self::search_transactions_before_linear`]): `AccountsHistory` skips storage-only
    /// changes (revm's `to_plain_state_reverts` drops `AccountInfoRevert::DoNothing` accounts),
    /// so the index would hide most incoming calls to e.g. an ERC-20.
    async fn search_transactions_before(
        &self,
        address: Address,
        block_number: LenientBlockNumberOrTag,
        page_size: usize,
    ) -> RpcResult<TransactionsWithReceipts<RpcTransaction<Eth::NetworkTypes>>> {
        let is_contract = {
            let state = self.eth.latest_state().map_err(|e| internal_rpc_err(e.to_string()))?;
            let account =
                state.basic_account(&address).map_err(|e| internal_rpc_err(e.to_string()))?;

            let Some(account) = account else {
                return Err(EthApiError::InvalidParams(
                    "invalid parameter: address does not exist".to_string(),
                )
                .into());
            };

            account.bytecode_hash.is_some_and(|hash| hash != KECCAK_EMPTY)
        };

        let tip: u64 = self.eth.block_number()?.saturating_to();

        let block_number: u64 = match block_number.into_inner() {
            BlockNumberOrTag::Number(n) => n,
            BlockNumberOrTag::Earliest => 0,
            _ => tip,
        };

        if block_number > tip {
            return Err(EthApiError::InvalidParams(
                "invalid parameter: block number is larger than the chain tip".to_string(),
            )
            .into());
        }

        // Since the results are in reverse chronological order, if the search starts from the tip
        // of the chain (block_number == 0) then it is the first page. If the search reaches
        // the genesis block, then it is the last page
        let mut txs_with_receipts = TransactionsWithReceipts {
            txs: Vec::default(),
            receipts: Vec::default(),
            first_page: block_number == 0,
            last_page: false,
        };

        let filter = TraceFilter {
            from_block: None,
            to_block: None,
            from_address: vec![address],
            to_address: vec![address],
            mode: TraceFilterMode::Union,
            after: None,
            count: None,
        };

        let matcher = Arc::new(filter.matcher());
        let cur_block = if block_number == 0 { tip } else { block_number - 1 };

        // Contracts go straight to the exhaustive linear scan: the account-history index skips
        // storage-only changes and would hide most incoming calls (see the handler docs).
        let mut linear_fallback = is_contract;

        if !linear_fallback {
            // Exclusive upper bound for the candidate query: inspect blocks <= `cur_block`.
            let mut before = cur_block + 1;

            // iterate over the candidate blocks (blocks in which the account's state changed,
            // newest first) until `page_size` transactions are found or the index is exhausted
            while txs_with_receipts.txs.len() < page_size {
                let candidates = match self.eth.provider().account_changed_blocks_before(
                    address,
                    before,
                    CANDIDATE_BATCH_SIZE,
                ) {
                    Ok(candidates) => candidates,
                    Err(_) if before == cur_block + 1 => {
                        // The first index probe failed: the index is unusable (e.g. account
                        // history is pruned), fall back to the exhaustive linear scan.
                        linear_fallback = true;
                        break;
                    }
                    Err(err) => return Err(internal_rpc_err(err.to_string())),
                };

                if candidates.is_empty() {
                    // No more changes below the cursor: equivalent to having reached genesis.
                    txs_with_receipts.last_page = true;
                    break;
                }

                // candidates are descending: continue strictly below the smallest one next round
                before = *candidates.last().expect("candidates is not empty");

                // trace only the candidate blocks; false positives (state changes not caused by
                // a matching transaction) are filtered out by the matcher
                let blocks = self.recovered_blocks(&candidates)?;
                self.collect_matching_transactions(blocks, &matcher, &mut txs_with_receipts)
                    .await?;
            }
        }

        if linear_fallback {
            self.search_transactions_before_linear(
                &matcher,
                &mut txs_with_receipts,
                cur_block,
                page_size,
            )
            .await?;
        }

        // Zip and sort transactions and receipts together by block number
        let mut tx_receipt_pairs: Vec<_> =
            txs_with_receipts.txs.into_iter().zip(txs_with_receipts.receipts).collect();

        tx_receipt_pairs.sort_by_key(|(tx, _)| {
            Reverse(tx.block_number().expect("Transactions on chain must have block number"))
        });

        // Get page_size number of transactions. If the page size is reached while within a
        // block, all transactions in that block are included even if it exceeds the page_number
        let (paginated_txs, paginated_receipts): (Vec<_>, Vec<_>) = tx_receipt_pairs
            .into_iter()
            .scan((None, 0), |(current_block_number, count), (tx, receipt)| {
                let block_number =
                    tx.block_number().expect("Transactions on chain must have block number");
                if *count >= page_size && *current_block_number != Some(block_number) {
                    return None;
                }
                if *current_block_number != Some(block_number) {
                    *current_block_number = Some(block_number);
                }
                *count += 1;
                Some((tx, receipt))
            })
            .unzip();

        txs_with_receipts.txs = paginated_txs.into_iter().collect();
        txs_with_receipts.receipts = paginated_receipts.into_iter().collect();

        Ok(txs_with_receipts)
    }

    /// Handler for `ots_searchTransactionsAfter`
    ///
    /// For EOAs, candidate blocks are selected via the account-history index (see
    /// [`AccountHistoryReader`]) instead of linearly re-executing every block of the chain. An
    /// EOA's state-change history is effectively complete: any value transfer or outgoing
    /// transaction changes its balance and/or nonce. The only misses are zero-value incoming
    /// `CALL`s and reverted incoming calls (which Erigon's call index would list) — a deliberate
    /// trade for bounded query cost. If the account-history index is unusable (e.g. account
    /// history is pruned), the EOA path falls back to the exhaustive linear scan.
    ///
    /// Contracts intentionally keep the exhaustive trace-based linear scan
    /// ([`Self::search_transactions_after_linear`]): `AccountsHistory` skips storage-only
    /// changes (revm's `to_plain_state_reverts` drops `AccountInfoRevert::DoNothing` accounts),
    /// so the index would hide most incoming calls to e.g. an ERC-20.
    async fn search_transactions_after(
        &self,
        address: Address,
        block_number: LenientBlockNumberOrTag,
        page_size: usize,
    ) -> RpcResult<TransactionsWithReceipts<RpcTransaction<Eth::NetworkTypes>>> {
        let is_contract = {
            let state = self.eth.latest_state().map_err(|e| internal_rpc_err(e.to_string()))?;
            let account =
                state.basic_account(&address).map_err(|e| internal_rpc_err(e.to_string()))?;

            let Some(account) = account else {
                return Err(EthApiError::InvalidParams(
                    "invalid parameter: address does not exist".to_string(),
                )
                .into());
            };

            account.bytecode_hash.is_some_and(|hash| hash != KECCAK_EMPTY)
        };

        let tip: u64 = self.eth.block_number()?.saturating_to();

        let block_number: u64 = match block_number.into_inner() {
            BlockNumberOrTag::Number(n) => n,
            BlockNumberOrTag::Earliest => 0,
            _ => tip,
        };

        if block_number > tip {
            return Err(EthApiError::InvalidParams(
                "invalid parameter: block number is larger than the chain tip".to_string(),
            )
            .into());
        }

        // Since the results are in reverse chronological order, if the search reaches the tip of
        // the chain then it is the first page. If the search starts from the genesis block,
        // then it is the last page
        let mut txs_with_receipts = TransactionsWithReceipts {
            txs: Vec::default(),
            receipts: Vec::default(),
            first_page: false,
            last_page: block_number == 0,
        };

        let filter = TraceFilter {
            from_block: None,
            to_block: None,
            from_address: vec![address],
            to_address: vec![address],
            mode: TraceFilterMode::Union,
            after: None,
            count: None,
        };

        let matcher = Arc::new(filter.matcher());

        // Contracts go straight to the exhaustive linear scan: the account-history index skips
        // storage-only changes and would hide most incoming calls (see the handler docs).
        let mut linear_fallback = is_contract;

        if !linear_fallback {
            // Strictly-above cursor for the candidate query. The linear implementation starts
            // the scan at `block_number + 1` (or at block 0 for a genesis search); the genesis
            // block holds no transactions, so starting strictly above 0 is equivalent.
            let mut after = block_number;

            // iterate over the candidate blocks (blocks in which the account's state changed,
            // oldest first) until `page_size` transactions are found or the index is exhausted
            while txs_with_receipts.txs.len() < page_size {
                let candidates = match self.eth.provider().account_changed_blocks_after(
                    address,
                    after,
                    CANDIDATE_BATCH_SIZE,
                ) {
                    Ok(candidates) => candidates,
                    Err(_) if after == block_number => {
                        // The first index probe failed: the index is unusable (e.g. account
                        // history is pruned), fall back to the exhaustive linear scan.
                        linear_fallback = true;
                        break;
                    }
                    Err(err) => return Err(internal_rpc_err(err.to_string())),
                };

                // candidates are ascending: continue strictly above the largest one next round.
                // Advance the cursor before filtering against the tip to guarantee progress.
                let Some(&last_candidate) = candidates.last() else {
                    // No more changes above the cursor: the search has reached the tip of the
                    // chain meaning this is the first page of the transactions.
                    txs_with_receipts.first_page = true;
                    break;
                };
                after = last_candidate;

                // Defensively ignore candidates beyond the tip observed above (the index
                // snapshot may be slightly ahead of it). Since candidates are ascending, an
                // empty result here means everything left is above the tip.
                let candidates =
                    candidates.into_iter().filter(|block| *block <= tip).collect::<Vec<_>>();
                if candidates.is_empty() {
                    txs_with_receipts.first_page = true;
                    break;
                }

                // trace only the candidate blocks; false positives (state changes not caused by
                // a matching transaction) are filtered out by the matcher
                let blocks = self.recovered_blocks(&candidates)?;
                self.collect_matching_transactions(blocks, &matcher, &mut txs_with_receipts)
                    .await?;
            }
        }

        if linear_fallback {
            let cur_block = if block_number == 0 { 0 } else { block_number + 1 };
            self.search_transactions_after_linear(
                &matcher,
                &mut txs_with_receipts,
                cur_block,
                tip,
                page_size,
            )
            .await?;
        }

        // Zip and sort transactions and receipts together by block number
        let mut tx_receipt_pairs: Vec<_> =
            txs_with_receipts.txs.into_iter().zip(txs_with_receipts.receipts).collect();

        tx_receipt_pairs.sort_by_key(|(tx, _)| {
            tx.block_number().expect("Transactions on chain must have block number")
        });

        // Get page_size number of transactions. If the page size is reached while within a
        // block, all transactions in that block are included even if it exceeds the page_number
        let (paginated_txs, paginated_receipts): (Vec<_>, Vec<_>) = tx_receipt_pairs
            .into_iter()
            .scan((None, 0), |(current_block_number, count), (tx, receipt)| {
                let block_number =
                    tx.block_number().expect("Transactions on chain must have block number");
                if *count >= page_size && *current_block_number != Some(block_number) {
                    return None;
                }
                if *current_block_number != Some(block_number) {
                    *current_block_number = Some(block_number);
                }
                *count += 1;
                Some((tx, receipt))
            })
            .unzip();

        // Reverse the order of the transactions to make the most recent ones appear first
        txs_with_receipts.txs = paginated_txs.into_iter().rev().collect();
        txs_with_receipts.receipts = paginated_receipts.into_iter().rev().collect();

        Ok(txs_with_receipts)
    }

    /// Handler for `ots_getTransactionBySenderAndNonce`
    async fn get_transaction_by_sender_and_nonce(
        &self,
        sender: Address,
        nonce: u64,
    ) -> RpcResult<Option<TxHash>> {
        Ok(self
            .eth
            .get_transaction_by_sender_and_nonce(sender, nonce, false)
            .await
            .map_err(Into::into)?
            .map(|tx| tx.tx_hash()))
    }

    /// Handler for `ots_getContractCreator`
    async fn get_contract_creator(&self, address: Address) -> RpcResult<Option<ContractCreator>> {
        if !self.has_code(address, None).await? {
            return Ok(None);
        }

        let num = binary_search::<_, _, ErrorObjectOwned>(
            1,
            self.eth.block_number()?.saturating_to(),
            |mid| {
                Box::pin(async move {
                    Ok(!EthApiServer::get_code(&self.eth, address, Some(mid.into()))
                        .await?
                        .is_empty())
                })
            },
        )
        .await?;

        let traces = self
            .eth
            .trace_block_with(
                num.into(),
                None,
                TracingInspectorConfig::default_parity(),
                |tx_info, mut ctx| {
                    Ok(ctx
                        .take_inspector()
                        .into_parity_builder()
                        .into_localized_transaction_traces(tx_info))
                },
            )
            .await
            .map_err(Into::into)?
            .map(|traces| {
                traces
                    .into_iter()
                    .flatten()
                    .map(|tx_trace| {
                        let trace = tx_trace.trace;
                        Ok(match (trace.action, trace.result, trace.error) {
                            (
                                Action::Create(CreateAction { from: creator, .. }),
                                Some(TraceOutput::Create(CreateOutput {
                                    address: contract, ..
                                })),
                                None,
                            ) if contract == address => Some(ContractCreator {
                                hash: tx_trace
                                    .transaction_hash
                                    .ok_or(EthApiError::TransactionNotFound)?,
                                creator,
                            }),
                            _ => None,
                        })
                    })
                    .filter_map(Result::transpose)
                    .collect::<Result<Vec<_>, EthApiError>>()
            })
            .transpose()?;

        // A contract maybe created and then destroyed in multiple transactions, here we
        // return the first found transaction, this behavior is consistent with etherscan's
        let found = traces.and_then(|traces| traces.first().copied());
        Ok(found)
    }
}

/// Returns the transaction slice for an Otterscan block page.
///
/// Otterscan paginates in block order, so page `0` corresponds to the first transactions in the
/// block instead of the tail.
fn block_transaction_page_range(
    tx_len: usize,
    page_number: usize,
    page_size: usize,
) -> std::ops::Range<usize> {
    let page_start = page_number.saturating_mul(page_size).min(tx_len);
    let page_end = page_start.saturating_add(page_size).min(tx_len);
    page_start..page_end
}

#[cfg(test)]
mod tests {
    use super::block_transaction_page_range;

    #[test]
    fn block_transaction_page_range_returns_first_pages_in_block_order() {
        assert_eq!(block_transaction_page_range(25, 0, 10), 0..10);
        assert_eq!(block_transaction_page_range(25, 1, 10), 10..20);
    }

    #[test]
    fn block_transaction_page_range_caps_pages_at_the_block_length() {
        assert_eq!(block_transaction_page_range(25, 2, 10), 20..25);
        assert_eq!(block_transaction_page_range(25, 3, 10), 25..25);
    }
}
