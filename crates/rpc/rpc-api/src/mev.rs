use alloy_rpc_types_mev::{EthBundleHash, MevSendBundle, SimBundleOverrides, SimBundleResponse};
use jsonrpsee::proc_macros::rpc;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

/// A `mev_simBundle` bundle, decoded as leniently as the Flashbots builder decodes it.
///
/// [`MevSendBundle`] is stricter than the Flashbots builder in two places, and mev-share-node
/// depends on the builder's behavior in both:
/// - It requires `canRevert` on every transaction item. The builder treats a missing `canRevert` as
///   `false`, and mev-share-node omits it when false.
/// - It rejects privacy hints it does not know, such as `special_logs`. The builder's
///   `mev_simBundle` has no privacy field and ignores it.
///
/// So before decoding, this adds a missing `canRevert` as `false` and drops `privacy`, at every
/// level of nesting. A simulation does not use privacy.
#[derive(Debug, Clone, Serialize)]
#[serde(transparent)]
pub struct SimBundleRequest(pub MevSendBundle);

impl<'de> Deserialize<'de> for SimBundleRequest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut bundle = Value::deserialize(deserializer)?;
        normalize_sim_bundle(&mut bundle);
        serde_json::from_value(bundle).map(Self).map_err(serde::de::Error::custom)
    }
}

impl From<MevSendBundle> for SimBundleRequest {
    fn from(bundle: MevSendBundle) -> Self {
        Self(bundle)
    }
}

fn normalize_sim_bundle(bundle: &mut Value) {
    let Some(bundle) = bundle.as_object_mut() else { return };
    bundle.remove("privacy");
    let Some(body) = bundle.get_mut("body").and_then(Value::as_array_mut) else { return };
    for item in body {
        let Some(item) = item.as_object_mut() else { continue };
        if item.contains_key("tx") {
            item.entry("canRevert").or_insert(Value::Bool(false));
        }
        if let Some(nested) = item.get_mut("bundle") {
            normalize_sim_bundle(nested);
        }
    }
}

/// Mev rpc interface.
#[cfg_attr(not(feature = "client"), rpc(server, namespace = "mev"))]
#[cfg_attr(feature = "client", rpc(server, client, namespace = "mev"))]
pub trait MevSimApi {
    /// Similar to `mev_sendBundle` but instead of submitting a bundle to the relay, it returns
    /// a simulation result. Only fully matched bundles can be simulated.
    #[method(name = "simBundle")]
    async fn sim_bundle(
        &self,
        bundle: SimBundleRequest,
        sim_overrides: Option<SimBundleOverrides>,
    ) -> jsonrpsee::core::RpcResult<SimBundleResponse>;
}

/// Mev rpc interface.
#[cfg_attr(not(feature = "client"), rpc(server, namespace = "mev"))]
#[cfg_attr(feature = "client", rpc(server, client, namespace = "mev"))]
pub trait MevFullApi {
    /// Submitting bundles to the relay. It takes in a bundle and provides a bundle hash as a
    /// return value.
    #[method(name = "sendBundle")]
    async fn send_bundle(
        &self,
        request: MevSendBundle,
    ) -> jsonrpsee::core::RpcResult<EthBundleHash>;

    /// Similar to `mev_sendBundle` but instead of submitting a bundle to the relay, it returns
    /// a simulation result. Only fully matched bundles can be simulated.
    #[method(name = "simBundle")]
    async fn sim_bundle(
        &self,
        bundle: SimBundleRequest,
        sim_overrides: Option<SimBundleOverrides>,
    ) -> jsonrpsee::core::RpcResult<SimBundleResponse>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_rpc_types_mev::BundleItem;

    /// The bundle mev-share-node sends: no `canRevert` on a non-reverting transaction, and a
    /// `special_logs` hint.
    #[test]
    fn decodes_a_mev_share_node_bundle() {
        let json = r#"{
            "version": "v0.1",
            "inclusion": {"block": "0x1", "maxBlock": "0x2"},
            "body": [
                {"tx": "0x01"},
                {"bundle": {
                    "version": "v0.1",
                    "inclusion": {"block": "0x1"},
                    "body": [{"tx": "0x02", "canRevert": true}],
                    "privacy": {"hints": ["special_logs"]}
                }}
            ],
            "privacy": {"hints": ["calldata", "special_logs"]}
        }"#;

        let SimBundleRequest(bundle) = serde_json::from_str(json).unwrap();

        assert!(bundle.privacy.is_none());
        let BundleItem::Tx { can_revert, .. } = &bundle.bundle_body[0] else { panic!() };
        assert!(!can_revert);
        let BundleItem::Bundle { bundle: nested } = &bundle.bundle_body[1] else { panic!() };
        assert!(nested.privacy.is_none());
        let BundleItem::Tx { can_revert, .. } = &nested.bundle_body[0] else { panic!() };
        assert!(can_revert);
    }

    /// Without the normalization, the same bundle fails to decode.
    #[test]
    fn mev_send_bundle_rejects_the_same_bundle() {
        let json =
            r#"{"version": "v0.1", "inclusion": {"block": "0x1"}, "body": [{"tx": "0x01"}]}"#;
        assert!(serde_json::from_str::<MevSendBundle>(json).is_err());
        assert!(serde_json::from_str::<SimBundleRequest>(json).is_ok());
    }

    /// mev-share-node sends the timeout as a decimal number of milliseconds.
    #[test]
    fn decodes_a_decimal_timeout() {
        let overrides: SimBundleOverrides =
            serde_json::from_str(r#"{"parentBlock": null, "timeout": 500}"#).unwrap();
        assert_eq!(overrides.timeout, Some(500));
    }
}
