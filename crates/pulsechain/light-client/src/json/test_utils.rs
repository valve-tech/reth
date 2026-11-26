//! Test helpers that other crates share: the spec's `light_client/sync` updates, and updates in
//! the form each endpoint gives them.

use super::{empty_committee, zero_branch, UpdateKind};
use crate::sync_committee::{
    test_utils::{bytes, case_beacon, hash},
    Gindices, LightClientBootstrap, LightClientHeader, LightClientUpdate, Preset,
};
use alloy_primitives::B256;
use reth_pulsechain_forks::network::{BeaconFork, PulsechainBeacon};
use serde_json::Value;

/// The `light_client/sync` Capella case.
pub const CAPELLA_SYNC: &str =
    include_str!("../../testdata/sync_committee/sync_capella_light_client_sync.json");

/// A `light_client/sync` case whose bootstrap and updates are all at `fork`: its pins, trusted
/// block root, bootstrap, and updates with their current slots.
pub fn sync_case(
    json: &str,
    fork: BeaconFork,
) -> (PulsechainBeacon, B256, LightClientBootstrap, Vec<(LightClientUpdate, u64)>) {
    let case: Value = serde_json::from_str(json).unwrap();
    let preset = Preset::MINIMAL;
    let bootstrap =
        LightClientBootstrap::from_ssz_bytes(&bytes(&case["bootstrap"]), preset, fork).unwrap();
    let updates = case["steps"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|step| step.get("process_update"))
        .map(|step| {
            let ssz = bytes(&step["update"]);
            let update = LightClientUpdate::from_ssz_bytes(&ssz, preset, fork).unwrap();
            (update, step["current_slot"].as_u64().unwrap())
        })
        .collect();
    (case_beacon(&case), hash(&case["trusted_block_root"]), bootstrap, updates)
}

/// The `light_client/sync` Capella case: its pins, bootstrap, and updates with their current
/// slots.
pub fn capella_case(
) -> (PulsechainBeacon, B256, LightClientBootstrap, Vec<(LightClientUpdate, u64)>) {
    sync_case(CAPELLA_SYNC, BeaconFork::Capella)
}

/// `update` as the endpoint for `kind` gives it: the fields it does not carry at defaults.
pub fn as_kind(update: &LightClientUpdate, kind: UpdateKind) -> LightClientUpdate {
    let gindices = Gindices::for_fork(BeaconFork::Capella).unwrap();
    let mut u = update.clone();
    if kind != UpdateKind::Full {
        u.next_sync_committee = empty_committee(Preset::MINIMAL);
        u.next_sync_committee_branch = zero_branch(gindices.next_sync_committee);
    }
    if kind == UpdateKind::Optimistic {
        u.finalized_header = LightClientHeader::default();
        u.finality_branch = zero_branch(gindices.finalized_root);
    }
    u
}
