use alloy_consensus::{constants::KECCAK_EMPTY, BlockHeader, Typed2718};
use alloy_eips::{eip1898::LenientBlockNumberOrTag, BlockId, BlockNumberOrTag};
use alloy_evm::block::calc::{base_block_reward, block_reward, ommer_reward};
use alloy_network::{primitives::HeaderResponse, ReceiptResponse, TransactionResponse};
use alloy_primitives::{Address, Bloom, Bytes, FixedBytes, TxHash, B256, U256};
use alloy_rpc_types_eth::{BlockTransactions, TransactionReceipt};
use alloy_rpc_types_trace::{
    filter::{TraceFilter, TraceFilterMatcher, TraceFilterMode},
    otterscan::{
        BlockDetails, ContractCreator, InternalIssuance, InternalOperation, OtsBlockTransactions,
        OtsReceipt, OtsTransactionReceipt, TraceEntry, TransactionsWithReceipts,
    },
    parity::{Action, CreateAction, CreateOutput, LocalizedTransactionTrace, TraceOutput},
};
use async_trait::async_trait;
use futures::{stream, StreamExt};
use jsonrpsee::{core::RpcResult, types::ErrorObjectOwned};
use reth_chainspec::ChainSpecProvider;
use reth_primitives_traits::{BlockBody, RecoveredBlock, TxTy};
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
    otterscan::InternalOperationsInspector,
    tracing::{
        types::{CallKind, CallTraceNode},
        TracingInspectorConfig,
    },
};
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
    Eth: FullEthApiTypes + TraceExt,
{
    /// Constructs a `BlockDetails` from a block and its receipts.
    async fn block_details(
        &self,
        block: RpcBlock<Eth::NetworkTypes>,
        receipts: Vec<RpcReceipt<Eth::NetworkTypes>>,
    ) -> RpcResult<BlockDetails<RpcHeader<Eth::NetworkTypes>>> {
        // Execution fees include the base fee; blob fees are not part of this field.
        let total_fees = receipts
            .iter()
            .map(|receipt| {
                U256::from(receipt.gas_used()) * U256::from(receipt.effective_gas_price())
            })
            .sum::<U256>();

        let chain_spec = self.eth.provider().chain_spec();
        let reward = if block.header.number() == 0 {
            None
        } else {
            base_block_reward(&chain_spec, block.header.number())
        };
        let issuance = if let Some(reward) = reward {
            let recovered = if block.uncles.is_empty() {
                None
            } else {
                Some(
                    self.eth
                        .recovered_block(block.header.hash().into())
                        .await
                        .map_err(Into::<ErrorObjectOwned>::into)?
                        .ok_or(EthApiError::HeaderNotFound(block.header.hash().into()))?,
                )
            };
            let ommers =
                recovered.as_ref().and_then(|block| block.body().ommers()).unwrap_or_default();
            calculate_issuance(
                reward,
                block.header.number(),
                ommers.iter().map(BlockHeader::number),
            )
        } else {
            InternalIssuance::default()
        };
        Ok(BlockDetails::new(block, issuance, total_fees))
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
        self.eth
            .spawn_trace_transaction_in_block_with_inspector(
                tx_hash,
                InternalOperationsInspector::default(),
                |_tx_info, inspector, _, _| Ok(inspector.into_operations()),
            )
            .await
            .map_err(Into::into)
            .map(Option::unwrap_or_default)
    }

    /// Handler for `ots_getTransactionError`
    async fn get_transaction_error(&self, tx_hash: TxHash) -> RpcResult<Option<Bytes>> {
        self.eth
            .spawn_replay_transaction(tx_hash, |_tx_info, res, _| Ok(transaction_error(res.result)))
            .await
            .map_err(Into::into)
    }

    /// Handler for `ots_traceTransaction`
    async fn trace_transaction(&self, tx_hash: TxHash) -> RpcResult<Option<Vec<TraceEntry>>> {
        self.eth
            .spawn_trace_transaction_in_block(
                tx_hash,
                TracingInspectorConfig::default_parity(),
                |_tx_info, inspector, _, _| {
                    Ok(otterscan_traces(inspector.into_traces().into_nodes()))
                },
            )
            .await
            .map_err(Into::into)
    }

    /// Handler for `ots_getBlockDetails`
    async fn get_block_details(
        &self,
        block_number: LenientBlockNumberOrTag,
    ) -> RpcResult<BlockDetails<RpcHeader<Eth::NetworkTypes>>> {
        let block_number = block_number.into_inner();
        let block = self.eth.block_by_number(block_number, false);
        let block_id = block_number.into();
        let receipts = self.eth.block_receipts(block_id);
        let (block, receipts) = futures::try_join!(block, receipts)?;
        self.block_details(
            block.ok_or(EthApiError::HeaderNotFound(block_id))?,
            receipts.ok_or(EthApiError::ReceiptsNotFound(block_id))?,
        )
        .await
    }

    /// Handler for `ots_getBlockDetailsByHash`
    async fn get_block_details_by_hash(
        &self,
        block_hash: B256,
    ) -> RpcResult<BlockDetails<RpcHeader<Eth::NetworkTypes>>> {
        let block = self.eth.block_by_hash(block_hash, false);
        let block_id = block_hash.into();
        let receipts = self.eth.block_receipts(block_id);
        let (block, receipts) = futures::try_join!(block, receipts)?;
        self.block_details(
            block.ok_or(EthApiError::HeaderNotFound(block_id))?,
            receipts.ok_or(EthApiError::ReceiptsNotFound(block_id))?,
        )
        .await
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
            .map(|traces| find_contract_creator(address, traces))
            .transpose()?;

        // Code-presence search assumes a single deployment. It cannot reliably identify
        // the first deployment of contracts that were destroyed and recreated.
        Ok(traces.flatten())
    }
}

/// Finds a creation that was not rolled back by its own frame or an enclosing frame.
fn find_contract_creator(
    address: Address,
    transactions: Vec<Vec<LocalizedTransactionTrace>>,
) -> Result<Option<ContractCreator>, EthApiError> {
    for traces in transactions {
        let mut reverted_path: Option<Vec<usize>> = None;
        for tx_trace in traces {
            let trace = tx_trace.trace;
            // Parity traces are in preorder, so a failed frame precedes its entire subtree.
            if reverted_path.as_ref().is_some_and(|path| trace.trace_address.starts_with(path)) {
                continue
            }
            reverted_path = None;
            if trace.error.is_some() {
                reverted_path = Some(trace.trace_address);
                continue
            }
            if let (
                Action::Create(CreateAction { from: creator, .. }),
                Some(TraceOutput::Create(CreateOutput { address: contract, .. })),
            ) = (trace.action, trace.result) &&
                contract == address
            {
                return Ok(Some(ContractCreator {
                    hash: tx_trace.transaction_hash.ok_or(EthApiError::TransactionNotFound)?,
                    creator,
                }))
            }
        }
    }
    Ok(None)
}

/// Returns the transaction slice for an Otterscan block page.
///
/// Pages are selected from the end of the block, retaining block order within each page.
/// The frontend reverses each page and uses this ordering for transaction-index links.
const fn block_transaction_page_range(
    tx_len: usize,
    page_number: usize,
    page_size: usize,
) -> std::ops::Range<usize> {
    let page_end = tx_len.saturating_sub(page_number.saturating_mul(page_size));
    let page_start = page_end.saturating_sub(page_size);
    page_start..page_end
}

/// Rewards issued to the miner (including ommer inclusion) and to the ommers themselves.
fn calculate_issuance(
    reward: u128,
    number: u64,
    ommer_numbers: impl ExactSizeIterator<Item = u64>,
) -> InternalIssuance {
    let block_reward = U256::from(block_reward(reward, ommer_numbers.len()));
    let uncle_reward =
        ommer_numbers.map(|ommer| U256::from(ommer_reward(reward, number, ommer))).sum::<U256>();
    InternalIssuance { block_reward, uncle_reward, issuance: block_reward + uncle_reward }
}

fn transaction_error<H>(result: ExecutionResult<H>) -> Bytes {
    match result {
        ExecutionResult::Revert { output, .. } => output,
        _ => Bytes::new(),
    }
}

/// A self-destruct is a separate operation at the end of its enclosing call, after any children.
fn otterscan_traces(nodes: Vec<CallTraceNode>) -> Vec<TraceEntry> {
    let mut entries = Vec::with_capacity(nodes.len());
    let mut selfdestructs: Vec<TraceEntry> = Vec::new();
    for CallTraceNode { trace, .. } in nodes {
        // The arena is in call-entry order. Emit completed calls' self-destructs before
        // entering a sibling or returning to an ancestor.
        while selfdestructs.last().is_some_and(|entry| entry.depth > trace.depth as u32) {
            entries.push(selfdestructs.pop().expect("checked above"));
        }
        if let Some(to) = trace.selfdestruct_refund_target {
            selfdestructs.push(TraceEntry {
                r#type: "SELFDESTRUCT".to_string(),
                depth: trace.depth as u32 + 1,
                from: trace.selfdestruct_address.unwrap_or(trace.address),
                to,
                value: trace.selfdestruct_transferred_value,
                input: Bytes::new(),
                output: Bytes::new(),
            });
        }
        entries.push(TraceEntry {
            r#type: trace.kind.to_string(),
            depth: trace.depth as u32,
            from: trace.caller,
            to: trace.address,
            value: (!matches!(trace.kind, CallKind::StaticCall | CallKind::DelegateCall))
                .then_some(trace.value),
            input: trace.data,
            output: trace.output,
        });
    }
    entries.extend(selfdestructs.into_iter().rev());
    entries
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{constants::ETH_TO_WEI, Header};
    use alloy_primitives::{hex, TxKind};
    use alloy_rpc_types_trace::parity::TransactionTrace;
    use reth_chainspec::MAINNET;
    use reth_evm_ethereum::EthEvmConfig;
    use reth_network_api::noop::NoopNetwork;
    use reth_provider::test_utils::MockEthProvider;
    use reth_transaction_pool::test_utils::testing_pool;
    use revm::{
        context::TxEnv,
        context_interface::result::{HaltReason, Output, SuccessReason},
        database::InMemoryDB,
        inspector::InspectorEvmTr,
        primitives::hardfork::SpecId,
        state::{AccountInfo, Bytecode},
        Context, InspectEvm, MainBuilder, MainContext,
    };
    use revm_inspectors::tracing::{types::CallTrace, TracingInspector};

    #[test]
    fn block_transaction_pages_match_frontend_index_navigation() {
        // The frontend requests floor((count - 1 - index) / size), then reverses the page.
        for count in [0, 1, 10, 25, 51] {
            for size in [1, 10, 25] {
                for index in 0..count {
                    let reverse_index = count - 1 - index;
                    let page = block_transaction_page_range(count, reverse_index / size, size);
                    let displayed = page.rev().collect::<Vec<_>>();
                    assert_eq!(displayed[reverse_index % size], index);
                }
            }
        }
        assert_eq!(block_transaction_page_range(25, 0, 10), 15..25);
        assert_eq!(block_transaction_page_range(25, 1, 10), 5..15);
        assert_eq!(block_transaction_page_range(25, 2, 10), 0..5);
        assert_eq!(block_transaction_page_range(25, 3, 10), 0..0);
        assert_eq!(block_transaction_page_range(25, usize::MAX, 10), 0..0);
        assert_eq!(block_transaction_page_range(25, 0, usize::MAX), 0..25);
        assert_eq!(block_transaction_page_range(25, 1, usize::MAX), 0..0);
        assert_eq!(block_transaction_page_range(25, 0, 0), 25..25);
    }

    #[test]
    fn transaction_error_returns_only_revert_data() {
        let success: ExecutionResult = ExecutionResult::Success {
            reason: SuccessReason::Return,
            gas: Default::default(),
            logs: vec![],
            output: Output::Call(Bytes::from_static(b"successful return data")),
        };
        let halt = ExecutionResult::Halt {
            reason: HaltReason::OutOfGas(revm::context_interface::result::OutOfGasError::Basic),
            gas: Default::default(),
            logs: vec![],
        };
        for result in [
            success,
            halt,
            ExecutionResult::Revert { gas: Default::default(), logs: vec![], output: Bytes::new() },
        ] {
            assert_eq!(serde_json::to_value(Some(transaction_error(result))).unwrap(), "0x");
        }
        let output = Bytes::from_static(b"revert data");
        assert_eq!(
            transaction_error::<HaltReason>(ExecutionResult::Revert {
                gas: Default::default(),
                logs: vec![],
                output: output.clone()
            }),
            output
        );
    }

    async fn cache_empty_block(
        cache: reth_rpc_eth_types::EthStateCache<reth_ethereum_primitives::EthPrimitives>,
        block: reth_ethereum_primitives::Block,
    ) {
        // MockEthProvider does not implement recovered_block; seed the normal RPC cache.
        let outcome = reth_execution_types::ExecutionOutcome::new(
            Default::default(),
            vec![vec![]],
            block.header.number,
            vec![],
        );
        let chain = reth_execution_types::Chain::new(
            [reth_primitives_traits::RecoveredBlock::new_unhashed(block, vec![])],
            outcome,
            Default::default(),
        );
        reth_rpc_eth_types::cache::cache_new_blocks_task(
            cache,
            futures::stream::iter([reth_chain_state::CanonStateNotification::Commit {
                new: std::sync::Arc::new(chain),
            }]),
        )
        .await;
    }

    #[tokio::test]
    async fn block_details_issuance_follows_chain_forks() {
        for (spec, number, reward) in [
            (0, 0),
            (1, 5),
            (4_369_999, 5),
            (4_370_000, 3),
            (7_279_999, 3),
            (7_280_000, 2),
            (15_537_393, 2),
            (15_537_394, 0),
        ]
        .into_iter()
        .map(|(number, reward)| (MAINNET.clone(), number, reward))
        .chain(std::iter::once((
            std::sync::Arc::new(
                reth_chainspec::ChainSpecBuilder::mainnet().paris_activated().build(),
            ),
            1,
            0,
        ))) {
            let provider = MockEthProvider::default().with_chain_spec((*spec).clone());
            let header = Header { number, ..Default::default() };
            let hash = header.hash_slow();
            let block = reth_ethereum_primitives::Block { header, body: Default::default() };
            provider.add_block(hash, block.clone());
            provider.add_receipts(number, vec![]);
            let api = OtterscanApi::new(
                crate::eth::EthApiBuilder::new(
                    provider,
                    testing_pool(),
                    NoopNetwork::default(),
                    EthEvmConfig::new(spec),
                )
                .build(),
            );
            cache_empty_block(api.eth.cache().clone(), block).await;
            let by_number = api
                .get_block_details(alloy_eips::BlockNumberOrTag::Number(number).into())
                .await
                .unwrap();
            let by_hash = api.get_block_details_by_hash(hash).await.unwrap();
            assert_eq!(
                by_number.issuance.block_reward,
                U256::from(reward * ETH_TO_WEI),
                "block {number}"
            );
            assert_eq!(by_number.issuance.uncle_reward, U256::ZERO);
            assert_eq!(by_number.issuance.issuance, by_number.issuance.block_reward);
            assert_eq!(by_number.issuance, by_hash.issuance);
        }
    }

    #[tokio::test]
    async fn block_details_loads_ommer_headers() {
        let provider = MockEthProvider::default();
        let block = reth_ethereum_primitives::Block {
            header: Header { number: 126, ..Default::default() },
            body: alloy_consensus::BlockBody {
                ommers: vec![Header { number: 123, ..Default::default() }],
                ..Default::default()
            },
        };
        let hash = block.header.hash_slow();
        provider.add_block(hash, block.clone());
        provider.add_receipts(126, vec![]);
        let api = OtterscanApi::new(
            crate::eth::EthApiBuilder::new(
                provider,
                testing_pool(),
                NoopNetwork::default(),
                EthEvmConfig::new(MAINNET.clone()),
            )
            .build(),
        );
        cache_empty_block(api.eth.cache().clone(), block).await;
        let expected = calculate_issuance(5 * ETH_TO_WEI, 126, [123].into_iter());
        assert_eq!(
            api.get_block_details(alloy_eips::BlockNumberOrTag::Number(126).into())
                .await
                .unwrap()
                .issuance,
            expected
        );
        assert_eq!(api.get_block_details_by_hash(hash).await.unwrap().issuance, expected);
    }

    #[tokio::test]
    async fn unknown_transactions_and_unimplemented_history_remain_distinct() {
        let api = OtterscanApi::new(
            crate::eth::EthApiBuilder::new(
                MockEthProvider::default(),
                testing_pool(),
                NoopNetwork::default(),
                EthEvmConfig::new(MAINNET.clone()),
            )
            .build(),
        );
        assert_eq!(api.get_api_level().await.unwrap(), 8);
        assert_eq!(api.get_transaction_error(B256::ZERO).await.unwrap(), None);
        assert_eq!(api.trace_transaction(B256::ZERO).await.unwrap(), None);
        assert!(api.get_internal_operations(B256::ZERO).await.unwrap().is_empty());
        assert!(api
            .get_block_details(alloy_eips::BlockNumberOrTag::Number(1).into())
            .await
            .is_err());
        assert!(api
            .get_block_transactions(alloy_eips::BlockNumberOrTag::Number(1).into(), 0, 10)
            .await
            .is_err());
        for error in [
            api.search_transactions_before(
                Address::ZERO,
                alloy_eips::BlockNumberOrTag::Number(0).into(),
                10,
            )
            .await
            .unwrap_err(),
            api.search_transactions_after(
                Address::ZERO,
                alloy_eips::BlockNumberOrTag::Number(0).into(),
                10,
            )
            .await
            .unwrap_err(),
        ] {
            assert_eq!(error.code(), -32603);
            assert_eq!(error.message(), "unimplemented");
        }
    }

    #[tokio::test]
    async fn execution_fees_use_full_u256_width() {
        let api = OtterscanApi::new(
            crate::eth::EthApiBuilder::new(
                MockEthProvider::default(),
                testing_pool(),
                NoopNetwork::default(),
                EthEvmConfig::new(MAINNET.clone()),
            )
            .build(),
        );
        let receipt = TransactionReceipt {
            inner: alloy_consensus::ReceiptEnvelope::Legacy(
                alloy_consensus::Receipt {
                    status: true.into(),
                    cumulative_gas_used: 2,
                    logs: vec![],
                }
                .with_bloom(),
            ),
            transaction_hash: B256::ZERO,
            transaction_index: Some(0),
            block_hash: Some(B256::ZERO),
            block_number: Some(0),
            gas_used: 2,
            effective_gas_price: u128::MAX,
            blob_gas_used: None,
            blob_gas_price: None,
            from: Address::ZERO,
            to: None,
            contract_address: None,
        };
        let details =
            api.block_details(Default::default(), vec![receipt.clone(), receipt]).await.unwrap();
        assert_eq!(details.total_fees, U256::from(u128::MAX) * U256::from(4));
    }

    #[test]
    fn issuance_includes_ommer_and_inclusion_rewards() {
        // A Frontier reward with an ommer three blocks behind.
        let issuance = calculate_issuance(5 * ETH_TO_WEI, 126, [123].into_iter());
        assert_eq!(issuance.block_reward, U256::from(5_156_250_000_000_000_000u128));
        assert_eq!(issuance.uncle_reward, U256::from(3_125_000_000_000_000_000u128));
        assert_eq!(issuance.issuance, U256::from(8_281_250_000_000_000_000u128));
        let issuance = calculate_issuance(2 * ETH_TO_WEI, 100, [99, 94].into_iter());
        assert_eq!(issuance.block_reward, U256::from(2_125_000_000_000_000_000u128));
        assert_eq!(issuance.uncle_reward, U256::from(2_250_000_000_000_000_000u128));
    }

    fn execute(code: Bytes, spec: SpecId) -> (ExecutionResult, Vec<TraceEntry>) {
        let contract = Address::repeat_byte(0x11);
        let mut db = InMemoryDB::default();
        db.insert_account_info(
            Address::ZERO,
            AccountInfo { balance: U256::from(ETH_TO_WEI), ..Default::default() },
        );
        db.insert_account_info(
            contract,
            AccountInfo {
                balance: U256::from(100),
                code: Some(Bytecode::new_legacy(code)),
                ..Default::default()
            },
        );
        let mut evm = Context::mainnet()
            .modify_cfg_chained(|cfg| cfg.spec = spec)
            .with_db(db)
            .build_mainnet_with_inspector(TracingInspector::new(
                TracingInspectorConfig::default_parity(),
            ));
        let result = evm
            .inspect_tx(TxEnv {
                kind: TxKind::Call(contract),
                value: U256::from(7),
                gas_limit: 1_000_000,
                ..Default::default()
            })
            .unwrap();
        let (_, inspector) = evm.ctx_inspector();
        (result.result, otterscan_traces(inspector.traces().nodes().to_vec()))
    }

    #[test]
    fn selfdestruct_preserves_enclosing_call_and_beneficiary() {
        for spec in [SpecId::SHANGHAI, SpecId::CANCUN] {
            let (result, traces) = execute(hex!("6022ff").into(), spec);
            assert!(result.is_success());
            assert_eq!(traces.len(), 2);
            assert_eq!(traces[0].r#type, "CALL");
            assert_eq!(traces[0].depth, 0);
            assert_eq!(traces[0].value, Some(U256::from(7)));
            assert_eq!(traces[1].r#type, "SELFDESTRUCT");
            assert_eq!(traces[1].depth, 1);
            assert_eq!(traces[1].from, Address::repeat_byte(0x11));
            assert_eq!(traces[1].to, Address::with_last_byte(0x22));
            assert_eq!(traces[1].value, Some(U256::from(107)));
        }
    }

    #[test]
    fn selfdestruct_after_a_child_call_uses_enclosing_depth() {
        // Call another account, then destroy the root contract. The destruction is a sibling
        // of that call, not its child.
        let (result, traces) =
            execute(hex!("60006000600060006000603361fffff1506022ff").into(), SpecId::CANCUN);
        assert!(result.is_success());
        assert_eq!(traces.len(), 3);
        assert_eq!(traces[1].r#type, "CALL");
        assert_eq!(traces[1].depth, 1);
        assert_eq!(traces[2].r#type, "SELFDESTRUCT");
        assert_eq!(traces[2].depth, 1);
        assert_eq!(traces[2].from, Address::repeat_byte(0x11));
        assert_eq!(traces[2].to, Address::with_last_byte(0x22));
    }

    #[test]
    fn selfdestructs_follow_children_and_precede_siblings() {
        let nodes = [0, 1, 2, 1]
            .into_iter()
            .enumerate()
            .map(|(idx, depth)| CallTraceNode {
                trace: CallTrace {
                    depth,
                    address: Address::with_last_byte(idx as u8),
                    selfdestruct_address: (idx < 3).then_some(Address::with_last_byte(idx as u8)),
                    selfdestruct_refund_target: (idx < 3).then_some(Address::with_last_byte(0xff)),
                    selfdestruct_transferred_value: (idx < 3).then_some(U256::ZERO),
                    ..Default::default()
                },
                ..Default::default()
            })
            .collect();
        let traces = otterscan_traces(nodes);
        let order =
            traces.iter().map(|trace| (trace.r#type.as_str(), trace.depth)).collect::<Vec<_>>();
        assert_eq!(
            order,
            [
                ("CALL", 0),
                ("CALL", 1),
                ("CALL", 2),
                ("SELFDESTRUCT", 3),
                ("SELFDESTRUCT", 2),
                ("CALL", 1),
                ("SELFDESTRUCT", 1)
            ]
        );
        assert_eq!(
            traces
                .iter()
                .filter(|trace| trace.r#type == "SELFDESTRUCT")
                .map(|trace| trace.from)
                .collect::<Vec<_>>(),
            [Address::with_last_byte(2), Address::with_last_byte(1), Address::ZERO]
        );
    }

    #[test]
    fn precompile_calls_remain_in_transaction_traces() {
        let (result, traces) =
            execute(hex!("60006000600060006000600461fffff15000").into(), SpecId::CANCUN);
        assert!(result.is_success());
        assert_eq!(traces.len(), 2);
        assert_eq!(traces[1].to, Address::with_last_byte(4));
    }

    #[test]
    fn contract_creator_ignores_reverted_ancestors() {
        let contract = Address::repeat_byte(0x11);
        let creator = Address::repeat_byte(0x22);
        let localize = |trace, hash| LocalizedTransactionTrace {
            trace,
            transaction_hash: Some(hash),
            block_hash: None,
            block_number: Some(1),
            transaction_position: None,
        };
        let creation = TransactionTrace {
            action: Action::Create(CreateAction { from: creator, ..Default::default() }),
            result: Some(TraceOutput::Create(CreateOutput {
                address: contract,
                code: Bytes::new(),
                gas_used: 0,
            })),
            trace_address: vec![0, 0],
            ..Default::default()
        };
        for path in [vec![], vec![0]] {
            let failed = TransactionTrace {
                trace_address: path,
                error: Some("Reverted".into()),
                ..Default::default()
            };
            let reverted =
                vec![localize(failed, B256::ZERO), localize(creation.clone(), B256::ZERO)];
            assert_eq!(find_contract_creator(contract, vec![reverted.clone()]).unwrap(), None);
            let successful = vec![localize(creation.clone(), B256::repeat_byte(1))];
            assert_eq!(
                find_contract_creator(contract, vec![reverted, successful]).unwrap(),
                Some(ContractCreator { creator, hash: B256::repeat_byte(1) })
            );
        }
        // A reverted sibling does not invalidate a subsequent successful creation.
        let failed = TransactionTrace {
            trace_address: vec![0],
            error: Some("Reverted".into()),
            ..Default::default()
        };
        let successful = TransactionTrace { trace_address: vec![1], ..creation };
        assert!(find_contract_creator(
            contract,
            vec![vec![localize(failed, B256::ZERO), localize(successful, B256::ZERO)]]
        )
        .unwrap()
        .is_some());
    }

    #[test]
    fn static_and_delegate_calls_have_no_value() {
        // STATICCALL, DELEGATECALL and CALLCODE to 0x22 do not transfer ETH.
        let (result, traces) = execute(
            hex!("6000600060006000602261fffffa506000600060006000602261fffff45060006000600060006001602261fffff25000").into(),
            SpecId::CANCUN,
        );
        assert!(result.is_success());
        assert_eq!(traces.len(), 4);
        assert_eq!(traces[1].r#type, "STATICCALL");
        assert_eq!(traces[1].value, None);
        assert_eq!(traces[2].r#type, "DELEGATECALL");
        assert_eq!(traces[2].value, None);
        assert_eq!(traces[3].r#type, "CALLCODE");
        assert_eq!(traces[3].value, Some(U256::from(1)));
    }
}
