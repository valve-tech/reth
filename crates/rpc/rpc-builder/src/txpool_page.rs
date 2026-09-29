//! Installs the valve keyset-paged `txpool` methods.

use jsonrpsee::core::RegisterMethodError;
use reth_rpc::TxPoolPageApi;
use reth_rpc_api::TxPoolPageApiServer;
use reth_rpc_eth_api::{RpcConvert, RpcTransaction};

use crate::{RethRpcModule, TransportRpcModules};

/// Adds `txpool_contentPage` and `txpool_inspectPage` to every transport whose
/// namespace list names `txpool`, and to no other.
///
/// `merge_configured` would add them to every transport, whatever its
/// namespace list says.
pub fn install_txpool_page_rpc<Pool, Eth>(
    modules: &mut TransportRpcModules,
    pool: Pool,
    converter: Eth,
) -> Result<(), RegisterMethodError>
where
    Eth: RpcConvert,
    TxPoolPageApi<Pool, Eth>: TxPoolPageApiServer<RpcTransaction<Eth::Network>>,
{
    modules.merge_if_module_configured(
        RethRpcModule::Txpool,
        TxPoolPageApi::new(pool, converter).into_rpc(),
    )
}

#[cfg(test)]
mod tests {
    use jsonrpsee::RpcModule;
    use reth_chainspec::MAINNET;
    use reth_rpc::eth::helpers::types::EthRpcConverter;
    use reth_rpc_eth_types::receipt::EthReceiptConverter;
    use reth_transaction_pool::test_utils::testing_pool;

    use super::*;
    use crate::TransportRpcModuleConfig;

    const PAGE_METHODS: [&str; 2] = ["txpool_contentPage", "txpool_inspectPage"];

    fn has(module: Option<&RpcModule<()>>, method: &str) -> bool {
        module.unwrap().method_names().any(|m| m == method)
    }

    /// HTTP names `txpool`, WS and IPC do not. Only HTTP gets the methods.
    #[test]
    fn page_methods_follow_the_txpool_namespace() {
        let mut modules = TransportRpcModules {
            config: TransportRpcModuleConfig::default()
                .with_http([RethRpcModule::Eth, RethRpcModule::Txpool])
                .with_ws([RethRpcModule::Eth])
                .with_ipc([RethRpcModule::Eth]),
            http: Some(RpcModule::new(())),
            ws: Some(RpcModule::new(())),
            ipc: Some(RpcModule::new(())),
        };
        let converter = EthRpcConverter::new(EthReceiptConverter::new(MAINNET.clone()));
        install_txpool_page_rpc(&mut modules, testing_pool(), converter).unwrap();

        for method in PAGE_METHODS {
            assert!(has(modules.http.as_ref(), method), "{method} is missing on http");
            assert!(!has(modules.ws.as_ref(), method), "{method} is on ws without txpool");
            assert!(!has(modules.ipc.as_ref(), method), "{method} is on ipc without txpool");
        }
    }
}
