//! The trusted roots that a light client's first store starts from: the chain's pin in the
//! network table with the bootstrap that ships at it, or an operator's root. reth-lite and the
//! light-client data server both start from one.

use crate::{
    json::parse_bootstrap,
    sync_committee::{LightClientBootstrap, Preset},
};
use alloy_primitives::B256;
use reth_pulsechain_forks::network::{BeaconCheckpoint, PulsechainBeacon};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The oldest [`Checkpoint`] a first store starts from, by its slot.
///
/// An old root is a risk. The older it is, the more past committees a hostile source can choose
/// from to sign a made-up chain of rotations, and sync-committee members are not slashed for
/// that. A month gives each release's pin a month of use and keeps the catch-up to about 32
/// periods: two or three `updates` requests.
///
/// The limit does not come from what the sources keep. lighthouse-pulse keeps less than the
/// spec's `MIN_EPOCHS_FOR_BLOCK_REQUESTS` (about 122 days). It builds a bootstrap from the block's
/// state, which a checkpoint-synced node deletes about one epoch after the block is finalized,
/// so a pin's bootstrap ships in the binary ([`shipped_bootstrap`]). It keeps the best update of
/// each period with no pruning, but only for periods it imported with `--light-client-server`
/// on, so the catch-up needs a source whose server ran since the checkpoint's period.
pub const MAX_CHECKPOINT_AGE: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// What an operator runs to get a fresh checkpoint root.
pub const REFRESH_HINT: &str = "crates/pulsechain/lite/scripts/checkpoint-root.sh <beacon-url> \
                                <check-url> in the reth source prints a recent finalized root \
                                and checks it against a second source";

/// `SECONDS_PER_SLOT` on every `PulseChain` network.
const SECONDS_PER_SLOT: u64 = 10;

/// A finalized beacon block root that a first store trusts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Checkpoint {
    /// The chain's pin in the `PulseChain` network table.
    Pinned(BeaconCheckpoint),
    /// `--checkpoint`, an operator's root. Its slot comes from the bootstrap header it proves.
    Flag(B256),
}

impl Checkpoint {
    /// The trusted block root.
    pub const fn root(&self) -> B256 {
        match self {
            Self::Pinned(pin) => pin.root,
            Self::Flag(root) => *root,
        }
    }
}

/// Returns the age in days, rounded up, of the block at `slot` on the chain of `pins` when it is
/// older than [`MAX_CHECKPOINT_AGE`] at `now`, and `None` when it is not.
pub fn stale_days(slot: u64, pins: &PulsechainBeacon, now: SystemTime) -> Option<u64> {
    let start = pins.genesis_time.saturating_add(slot.saturating_mul(SECONDS_PER_SLOT));
    let now = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let age_secs = now.saturating_sub(start);
    // Rounded up, so a refusal never names an age at the limit.
    (age_secs > MAX_CHECKPOINT_AGE.as_secs()).then(|| age_secs.div_ceil(86_400))
}

/// The bootstrap that ships with the binary at `root`, if one does.
///
/// A source may not serve a bootstrap at a pin: lighthouse-pulse builds one from the block's
/// state, and a node without `--reconstruct-historic-states` deletes that state at the next
/// finalization. So each pin ships with its bootstrap, made by
/// `crates/pulsechain/lite/scripts/checkpoint-bootstrap.py`. It is a source's answer like any
/// other: [`LightClientStore::bootstrap`](crate::sync_committee::LightClientStore::bootstrap)
/// checks it against the pinned root.
pub fn shipped_bootstrap(root: B256, preset: Preset) -> Option<LightClientBootstrap> {
    SHIPPED_BOOTSTRAPS
        .iter()
        .filter_map(|json| parse_bootstrap(json.as_bytes(), preset).ok())
        .find(|bootstrap| bootstrap.header.beacon.hash_tree_root() == root)
}

/// The bootstraps at the pins of the network table, as the beacon API gives them.
const SHIPPED_BOOTSTRAPS: [&str; 1] = [include_str!("../checkpoints/369.json")];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync_committee::LightClientStore;
    use reth_pulsechain_forks::network::{pulsechain_network, PULSECHAIN_NETWORKS};

    /// Each pin in the network table ships with its bootstrap, and the bootstrap proves a
    /// committee into the pinned root.
    #[test]
    fn every_pin_ships_a_bootstrap_that_proves_its_root() {
        for network in &PULSECHAIN_NETWORKS {
            let Some(pin) = network.checkpoint else { continue };
            let bootstrap = shipped_bootstrap(pin.root, Preset::PULSECHAIN)
                .unwrap_or_else(|| panic!("chain {} ships no bootstrap", network.chain_id));
            let store = LightClientStore::bootstrap(
                Preset::PULSECHAIN,
                network.beacon,
                pin.root,
                &bootstrap,
            )
            .unwrap();
            assert_eq!(store.finalized_header().beacon.slot, pin.slot);
        }
        // The 369 pin's execution block, as a public RPC gives it.
        let pin = pulsechain_network(369).unwrap().checkpoint;
        let execution = shipped_bootstrap(pin.unwrap().root, Preset::PULSECHAIN).unwrap().header;
        assert_eq!(execution.execution.block_number, 28_135_111);
        assert_eq!(
            execution.execution.block_hash,
            alloy_primitives::b256!(
                "0x3d5b305b855dea5b1c3297d45cbe6b3f22bbbf6c858411d796cc78a52accd2a8"
            )
        );
        assert!(shipped_bootstrap(B256::repeat_byte(7), Preset::PULSECHAIN).is_none());
    }

    /// A block at the limit is not stale; one a second older is, and its age is rounded up.
    #[test]
    fn a_checkpoint_past_the_limit_is_stale_by_whole_days() {
        let pins = pulsechain_network(369).unwrap().beacon;
        let at = |secs: u64| UNIX_EPOCH + Duration::from_secs(pins.genesis_time + 100 + secs);
        let limit = MAX_CHECKPOINT_AGE.as_secs();
        assert_eq!(stale_days(10, &pins, at(limit)), None);
        assert_eq!(stale_days(10, &pins, at(limit + 1)), Some(31));
        assert_eq!(stale_days(10, &pins, at(45 * 86_400)), Some(45));
        // A clock before the block is not an age.
        assert_eq!(stale_days(10, &pins, UNIX_EPOCH), None);
    }
}
