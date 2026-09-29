//! Keyset-paged variants of `txpool_content` and `txpool_inspect`.
//!
//! This is a valve fork extension. It lives in its own trait so that upstream's
//! [`TxPoolApi`](crate::TxPoolApiServer) stays unchanged.
//!
//! A page lists senders in ascending address order and never splits one
//! sender's transactions across pages. `next` in the response is the `after`
//! value for the following page, and it is `null` when no sender is left.
//! This follows geth's `debug_storageRangeAt` (`nextKey`) and
//! `debug_accountRange` (`next`).

use alloy_json_rpc::RpcObject;
use alloy_primitives::Address;
use alloy_rpc_types_txpool::{TxpoolContent, TxpoolInspect};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use serde::{Deserialize, Serialize};

/// Most senders a caller can ask for in one page, and the page size when the
/// caller gives no `limit`.
pub const TXPOOL_PAGE_MAX_SENDERS: usize = 1_000;

/// Serialized transaction bytes after which the node stops adding senders to
/// a page. A page always holds at least one sender, so one sender with more
/// than this can make a page larger.
pub const TXPOOL_PAGE_MAX_BYTES: usize = 16 * 1024 * 1024;

/// Keyset-paged txpool interface, `txpool_contentPage` and `txpool_inspectPage`.
#[cfg_attr(not(feature = "client"), rpc(server, namespace = "txpool"))]
#[cfg_attr(feature = "client", rpc(server, client, namespace = "txpool"))]
pub trait TxPoolPageApi<T: RpcObject> {
    /// Returns one page of `txpool_content`: the pending and queued
    /// transactions of the senders after `after`, in ascending address order.
    #[method(name = "contentPage")]
    async fn txpool_content_page(
        &self,
        request: Option<TxpoolPageRequest>,
    ) -> RpcResult<TxpoolContentPage<T>>;

    /// Returns one page of `txpool_inspect`, paged the same way as
    /// `txpool_contentPage`.
    #[method(name = "inspectPage")]
    async fn txpool_inspect_page(
        &self,
        request: Option<TxpoolPageRequest>,
    ) -> RpcResult<TxpoolInspectPage>;
}

/// Request for one page of senders.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TxpoolPageRequest {
    /// Most senders in the page. Defaults to, and must not exceed,
    /// [`TXPOOL_PAGE_MAX_SENDERS`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    /// The page starts at the first sender above this address. Omitted, the
    /// page starts at the lowest sender.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<Address>,
}

/// One page of `txpool_content`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(serialize = "T: Serialize", deserialize = "T: serde::de::DeserializeOwned"))]
pub struct TxpoolContentPage<T> {
    /// The `pending` and `queued` maps, as `txpool_content` returns them.
    #[serde(flatten)]
    pub content: TxpoolContent<T>,
    /// The `after` value for the next page, or `None` at the end of the pool.
    pub next: Option<Address>,
}

/// One page of `txpool_inspect`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxpoolInspectPage {
    /// The `pending` and `queued` maps, as `txpool_inspect` returns them.
    #[serde(flatten)]
    pub inspect: TxpoolInspect,
    /// The `after` value for the next page, or `None` at the end of the pool.
    pub next: Option<Address>,
}
