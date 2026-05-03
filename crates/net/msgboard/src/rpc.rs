//! `msgboard_*` RPC method implementations.
//!
//! [`MsgboardApi`] wraps an `Arc<MsgBoard>` and implements
//! [`MsgboardApiServer`]. The subscription converts the board's
//! `tokio::sync::broadcast` channel into a `Stream` via `BroadcastStream`,
//! silently dropping lagged notifications.

use std::{collections::HashMap, sync::Arc};

use alloy_primitives::{Bytes, B256};
use async_trait::async_trait;
use futures::{future::ready, StreamExt};
use jsonrpsee::{
    core::RpcResult, types::ErrorObjectOwned, PendingSubscriptionSink, SubscriptionMessage,
};
use reth_msgboard_types::{decode_validated_pow_msg, CheckedPoWMsg, MsgboardError};
use tokio_stream::wrappers::BroadcastStream;

use crate::{
    board::MsgBoard,
    rpc_api::{ContentFilter, MsgboardApiServer, MsgboardMsg, MsgboardStatus, NewMessagesFilter},
};

/// Subscription kind discriminator. Matches erigon-pulse's
/// `msgboard_subscribe(["newMessages", filter?])` shape.
const SUBSCRIPTION_KIND_NEW_MESSAGES: &str = "newMessages";

/// `msgboard_*` API implementation.
#[derive(Debug, Clone)]
pub struct MsgboardApi {
    board: Arc<MsgBoard>,
}

impl MsgboardApi {
    /// Create a new instance backed by the given shared board.
    pub fn new(board: Arc<MsgBoard>) -> Self {
        Self { board }
    }
}

#[async_trait]
impl MsgboardApiServer for MsgboardApi {
    async fn msgboard_add_message(&self, input: Bytes) -> RpcResult<B256> {
        // Mirror erigon-pulse `PoWMsgFromRLP`: decode + validate at the RPC
        // boundary so the board's hot path can trust its inputs and the
        // validation error code is identical to erigon's.
        let msg = decode_validated_pow_msg(input.as_ref()).map_err(msgboard_error_to_rpc)?;

        match self.board.add_local_msg(msg) {
            Ok(checked) => Ok(checked.hash),
            Err(err) => Err(msgboard_error_to_rpc(err)),
        }
    }

    async fn msgboard_categories(&self) -> RpcResult<Vec<B256>> {
        Ok(self.board.categories())
    }

    async fn msgboard_content(
        &self,
        filter: Option<ContentFilter>,
    ) -> RpcResult<HashMap<String, Vec<MsgboardMsg>>> {
        let filter = filter.unwrap_or_default();
        let msgs = match filter.category {
            Some(cat) => {
                self.board.category_msgs_filtered(&cat, filter.from_block, filter.to_block)
            }
            None => self.board.all_msgs_filtered(filter.from_block, filter.to_block),
        };
        let mut grouped: HashMap<String, Vec<MsgboardMsg>> = HashMap::new();
        for m in &msgs {
            let rpc = to_rpc_msg(m);
            // Lowercase 0x-hex matches alloy's Display impl and erigon-pulse output.
            let key = rpc.category.to_string();
            grouped.entry(key).or_default().push(rpc);
        }
        Ok(grouped)
    }

    async fn msgboard_get_message(&self, hash: B256) -> RpcResult<Option<MsgboardMsg>> {
        Ok(self.board.get_message(&hash).as_ref().map(|m| to_rpc_msg(m.as_ref())))
    }

    async fn msgboard_status(&self) -> RpcResult<MsgboardStatus> {
        let (enabled, head_block, count, size, work_multiplier, work_divisor) = self.board.status();
        Ok(MsgboardStatus { enabled, count, size, work_multiplier, work_divisor, head_block })
    }

    async fn msgboard_subscribe(
        &self,
        pending: PendingSubscriptionSink,
        kind: String,
        filter: Option<NewMessagesFilter>,
    ) -> jsonrpsee::core::SubscriptionResult {
        if kind != SUBSCRIPTION_KIND_NEW_MESSAGES {
            let err = ErrorObjectOwned::owned(
                -32602,
                format!("unsupported subscription kind: {kind:?}"),
                None::<()>,
            );
            pending.reject(err).await;
            return Ok(());
        }

        let category_filter = filter.and_then(|f| f.category);
        let sink = pending.accept().await?;
        let board = Arc::clone(&self.board);

        tokio::spawn(async move {
            let rx = board.subscribe();
            // `ready(result.ok())` is Unpin (unlike `async move` blocks),
            // which lets the FilterMap stream work inside `tokio::select!`.
            let mut stream = BroadcastStream::new(rx).filter_map(|result| ready(result.ok()));

            loop {
                tokio::select! {
                    _ = sink.closed() => break,
                    maybe_msg = stream.next() => {
                        let Some(checked) = maybe_msg else { break };
                        if let Some(want) = category_filter.as_ref() {
                            if &checked.msg.category != want {
                                continue;
                            }
                        }
                        let rpc_msg = to_rpc_msg(&checked);
                        let msg = match SubscriptionMessage::new(
                            sink.method_name(),
                            sink.subscription_id(),
                            &rpc_msg,
                        ) {
                            Ok(m) => m,
                            Err(err) => {
                                tracing::error!(
                                    target: "rpc::msgboard",
                                    %err,
                                    "failed to serialize subscription message"
                                );
                                break;
                            }
                        };
                        if sink.send(msg).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        Ok(())
    }
}

/// Map a [`MsgboardError`] to a JSON-RPC error with a code matching erigon-pulse.
///
/// `powmsg:` errors → `-32602` (InvalidParams, matching Go's `rpc.InvalidParamsError`).
/// `msgboard:` errors → `-32000` (default error code, matching Go's `defaultErrorCode`).
fn msgboard_error_to_rpc(err: MsgboardError) -> ErrorObjectOwned {
    let code = match &err {
        // powmsg: decode + validation errors → InvalidParams
        MsgboardError::InvalidVersion |
        MsgboardError::InvalidBlockHash |
        MsgboardError::InvalidNonce |
        MsgboardError::InvalidDifficulty |
        MsgboardError::InvalidData |
        MsgboardError::InvalidWork |
        MsgboardError::Rlp(_) |
        MsgboardError::MalformedIdList => -32602,
        // msgboard: board-level errors → default
        _ => -32000,
    };
    ErrorObjectOwned::owned(code, err.to_string(), None::<()>)
}

/// Convert a [`CheckedPoWMsg`] to the JSON-RPC response type.
///
/// The server-side `timestamp` is intentionally omitted — erigon-pulse's
/// `RPCPoWMsg` has no equivalent field, and clients depend on the spec
/// shape, not on internal bookkeeping.
fn to_rpc_msg(m: &CheckedPoWMsg) -> MsgboardMsg {
    MsgboardMsg {
        version: m.msg.version,
        block_hash: m.msg.block_hash,
        block_number: m.block_number,
        nonce: m.msg.nonce,
        work_multiplier: m.msg.work_multiplier,
        work_divisor: m.msg.work_divisor,
        category: m.msg.category,
        data: m.msg.data.clone(),
        hash: m.hash,
    }
}
