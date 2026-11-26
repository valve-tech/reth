//! One table entry per `PulseChain` network.
//!
//! Code that needs a per-network value looks it up here by chain ID, through
//! [`pulsechain_network`]. A new `PulseChain` network is one new entry in
//! [`PULSECHAIN_NETWORKS`], plus its chain spec static and hardfork list.
//!
//! Lookups go by chain ID, not by the hardfork list in a chain spec. A chain
//! spec read from a genesis file has no `PrimordialPulse` entry, but the node
//! still treats chain 369 or 943 as `PulseChain`.

use alloy_primitives::{b256, B256};
use reth_ethereum_forks::ChainHardforks;

use crate::{
    chainspec::{PULSECHAIN_MAINNET_CHAIN_ID, PULSECHAIN_TESTNET_V4_CHAIN_ID},
    hardfork::{
        PulsechainHardfork, PRIMORDIAL_PULSE_MAINNET_BLOCK, PRIMORDIAL_PULSE_MAINNET_TIMESTAMP,
        PRIMORDIAL_PULSE_TESTNET_V4_BLOCK, PRIMORDIAL_PULSE_TESTNET_V4_TIMESTAMP,
    },
};

/// The per-network values of one `PulseChain` network.
#[derive(Debug, Clone, Copy)]
pub struct PulsechainNetwork {
    /// The chain ID after `PrimordialPulse`.
    pub chain_id: u64,
    /// The `PrimordialPulse` block. Blocks below it are Ethereum blocks.
    pub primordial_pulse_block: u64,
    /// The timestamp of the `PrimordialPulse` block.
    pub primordial_pulse_timestamp: u64,
    /// The block gas limit the payload builder targets when `--builder.gaslimit` is unset.
    ///
    /// This is the live network's gas limit. reth's own default for a chain it does not
    /// name is 36M, which would vote the limit away from it.
    pub default_gas_limit: u64,
    /// The forks this binary implements for the network, with their activations.
    ///
    /// The chain spec parser refuses a spec for this chain ID whose forks differ.
    pub hardforks: fn() -> ChainHardforks,
    /// The beacon chain's genesis and fork schedule.
    pub beacon: PulsechainBeacon,
    /// A finalized beacon block that reth-lite's first sync-committee bootstrap trusts, or `None`
    /// when no beacon source for the chain was reachable to take one.
    pub checkpoint: Option<BeaconCheckpoint>,
}

/// A finalized beacon block root, pinned as a light client's trust root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BeaconCheckpoint {
    /// The beacon block root.
    pub root: B256,
    /// The block's slot. Its age decides whether the pin is still usable.
    pub slot: u64,
    /// The UTC date the root was read, as `YYYY-MM-DD`.
    pub taken: &'static str,
}

/// A beacon-chain fork, in activation order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BeaconFork {
    /// The genesis fork.
    Phase0,
    /// Adds the sync committee.
    Altair,
    /// Adds the execution payload.
    Bellatrix,
    /// Adds withdrawals to the execution payload.
    Capella,
}

/// One beacon fork with its fork version and first epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BeaconForkActivation {
    /// The fork.
    pub fork: BeaconFork,
    /// The fork version that goes into the signing domain from `epoch` on.
    pub version: [u8; 4],
    /// The first epoch of the fork.
    pub epoch: u64,
}

/// The beacon-chain values a light client checks sync-committee signatures with.
///
/// The values come from the lighthouse-pulse network configs and `genesis.ssz`. The 369 values
/// also match `checkpoint.pulsechain.com` (`/eth/v1/beacon/genesis` and
/// `/eth/v1/config/fork_schedule`, read 2026-11-23). Neither chain schedules Deneb.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PulsechainBeacon {
    /// The root of the genesis validator set. Every signing domain includes it.
    pub genesis_validators_root: B256,
    /// The start of slot 0, in seconds since the Unix epoch.
    pub genesis_time: u64,
    /// Every fork the chain schedules, oldest first. The first entry is `Phase0` at epoch 0.
    pub forks: [BeaconForkActivation; 4],
}

impl PulsechainBeacon {
    /// Returns the fork that is active at `epoch`.
    pub fn fork_at_epoch(&self, epoch: u64) -> &BeaconForkActivation {
        self.forks.iter().rev().find(|fork| fork.epoch <= epoch).unwrap_or(&self.forks[0])
    }
}

/// Every `PulseChain` network this node knows.
///
/// Refresh each [`PulsechainNetwork::checkpoint`] for every release. reth-lite refuses a
/// checkpoint older than its age limit (30 days), so a release with an old pin cannot start a new
/// `--head.verify=sync-committee` node without `--checkpoint`. Run
/// `crates/pulsechain/lite/scripts/checkpoint-root.sh -o
/// crates/pulsechain/light-client/checkpoints/<chain>.json <beacon-url> <check-url>` against two
/// independent beacon sources of the chain. It prints a finalized root, its slot, the date and
/// the header fields. It checks that the block and the finalized state hash to the root, and that
/// the second source calls the root finalized with the same header. It then writes the
/// light-client bootstrap at the root, which reth-lite ships. Replace the entry and its comment,
/// with both sources, and the header fields in reth-lite's
/// `the_369_checkpoint_is_the_root_of_its_header` test.
pub const PULSECHAIN_NETWORKS: [PulsechainNetwork; 2] = [
    PulsechainNetwork {
        chain_id: PULSECHAIN_MAINNET_CHAIN_ID,
        primordial_pulse_block: PRIMORDIAL_PULSE_MAINNET_BLOCK,
        primordial_pulse_timestamp: PRIMORDIAL_PULSE_MAINNET_TIMESTAMP,
        default_gas_limit: 45_000_000,
        hardforks: PulsechainHardfork::mainnet,
        beacon: PulsechainBeacon {
            genesis_validators_root: b256!(
                "0x3357ba0018a2582aeabe4ae847aa17d50a3a99aaeb66293c01f80a83aecd0c90"
            ),
            genesis_time: 1_683_785_555,
            forks: [
                BeaconForkActivation {
                    fork: BeaconFork::Phase0,
                    version: 0x0000_0369_u32.to_be_bytes(),
                    epoch: 0,
                },
                BeaconForkActivation {
                    fork: BeaconFork::Altair,
                    version: 0x0000_036a_u32.to_be_bytes(),
                    epoch: 1,
                },
                BeaconForkActivation {
                    fork: BeaconFork::Bellatrix,
                    version: 0x0000_036b_u32.to_be_bytes(),
                    epoch: 2,
                },
                BeaconForkActivation {
                    fork: BeaconFork::Capella,
                    version: 0x0000_036c_u32.to_be_bytes(),
                    epoch: 3,
                },
            ],
        },
        // Read from `https://checkpoint.pulsechain.com` (Checkpointz v0.24.0) on 2026-11-24:
        // `/eth/v1/beacon/blocks/finalized/root` and `states/finalized/finality_checkpoints`
        // (epoch 349049) gave this root. It does not serve `headers`, so the root was hashed
        // again from the header: slot, proposer and parent and state roots from
        // `/eth/v2/beacon/blocks/{root}`, and the body root from `latest_block_header` in the
        // SSZ of `/eth/v2/debug/beacon/states/finalized` (slot 11169568). That state hashes to
        // the block's state root, and `light-client/checkpoints/369.json` is the bootstrap built
        // from it (execution block 28135111, whose hash a public RPC gives too). A second,
        // independent node, `https://rpc-pulsechain.g4mm4.io/beacon-api` (Lighthouse-Pulse
        // v2.5.1), answers `headers/{root}` with `finalized: true`, `canonical: true` and the
        // same header fields (checked 2026-11-24).
        checkpoint: Some(BeaconCheckpoint {
            root: b256!("0xf82e4b1502b64aab652df724decfba3bc200a7a0548556c36af0c0a7977e19cd"),
            slot: 11_169_568,
            taken: "2026-11-24",
        }),
    },
    PulsechainNetwork {
        chain_id: PULSECHAIN_TESTNET_V4_CHAIN_ID,
        primordial_pulse_block: PRIMORDIAL_PULSE_TESTNET_V4_BLOCK,
        primordial_pulse_timestamp: PRIMORDIAL_PULSE_TESTNET_V4_TIMESTAMP,
        default_gas_limit: 30_000_000,
        hardforks: PulsechainHardfork::testnet_v4,
        beacon: PulsechainBeacon {
            genesis_validators_root: b256!(
                "0xd81664ba97279a6fa0832041b4aee6009172b4750a99467ff670a9faf3a34e64"
            ),
            genesis_time: 1_681_356_369,
            forks: [
                BeaconForkActivation {
                    fork: BeaconFork::Phase0,
                    version: 0x0000_0943_u32.to_be_bytes(),
                    epoch: 0,
                },
                BeaconForkActivation {
                    fork: BeaconFork::Altair,
                    version: 0x0000_0944_u32.to_be_bytes(),
                    epoch: 1,
                },
                BeaconForkActivation {
                    fork: BeaconFork::Bellatrix,
                    version: 0x0000_0945_u32.to_be_bytes(),
                    epoch: 2,
                },
                BeaconForkActivation {
                    fork: BeaconFork::Capella,
                    version: 0x0000_0946_u32.to_be_bytes(),
                    epoch: 4200,
                },
            ],
        },
        // No 943 beacon source was reachable to take a root from.
        checkpoint: None,
    },
];

/// Returns the `PulseChain` network with `chain_id`, or `None` for any other chain.
pub fn pulsechain_network(chain_id: u64) -> Option<&'static PulsechainNetwork> {
    PULSECHAIN_NETWORKS.iter().find(|network| network.chain_id == chain_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chainspec::{PULSECHAIN, PULSECHAIN_TESTNET_V4},
        hardfork::PulsechainHardfork,
    };
    use reth_chainspec::{ForkCondition, Hardforks};

    /// Each entry agrees with its chain spec static and hardfork list.
    #[test]
    fn entries_match_the_chain_specs() {
        for spec in [&*PULSECHAIN, &*PULSECHAIN_TESTNET_V4] {
            let network = pulsechain_network(spec.chain.id()).expect("a table entry");
            let table: Vec<_> =
                (network.hardforks)().forks_iter().map(|(f, c)| (f.name(), c)).collect();
            let static_spec: Vec<_> = spec.forks_iter().map(|(f, c)| (f.name(), c)).collect();
            assert_eq!(table, static_spec, "chain {}", network.chain_id);
            assert_eq!(
                spec.fork(PulsechainHardfork::PrimordialPulse),
                ForkCondition::Block(network.primordial_pulse_block),
                "chain {}",
                network.chain_id,
            );
        }
    }

    /// Each beacon schedule starts with `Phase0` at epoch 0 and lists every fork once, in order,
    /// with a distinct version.
    #[test]
    fn beacon_schedules_are_ordered_and_complete() {
        let order =
            [BeaconFork::Phase0, BeaconFork::Altair, BeaconFork::Bellatrix, BeaconFork::Capella];
        for network in PULSECHAIN_NETWORKS {
            let forks = network.beacon.forks;
            assert_eq!(forks.map(|f| f.fork), order, "chain {}", network.chain_id);
            assert_eq!(forks[0].epoch, 0, "chain {}", network.chain_id);
            for pair in forks.windows(2) {
                assert!(pair[0].epoch < pair[1].epoch, "chain {}", network.chain_id);
                assert_ne!(pair[0].version, pair[1].version, "chain {}", network.chain_id);
            }
        }
    }

    /// The fork at an epoch is the last one that started at or before it.
    #[test]
    fn fork_at_epoch_picks_the_latest_started_fork() {
        let testnet = pulsechain_network(PULSECHAIN_TESTNET_V4_CHAIN_ID).unwrap().beacon;
        assert_eq!(testnet.fork_at_epoch(0).fork, BeaconFork::Phase0);
        assert_eq!(testnet.fork_at_epoch(1).fork, BeaconFork::Altair);
        assert_eq!(testnet.fork_at_epoch(4199).fork, BeaconFork::Bellatrix);
        assert_eq!(testnet.fork_at_epoch(4200).version, [0, 0, 9, 0x46]);
        assert_eq!(testnet.fork_at_epoch(u64::MAX).fork, BeaconFork::Capella);
        let mainnet = pulsechain_network(PULSECHAIN_MAINNET_CHAIN_ID).unwrap().beacon;
        assert_eq!(mainnet.fork_at_epoch(3).version, [0, 0, 3, 0x6c]);
    }

    /// Days since 1970-01-01 of the civil date `YYYY-MM-DD` (Howard Hinnant's algorithm).
    fn days_from_civil(date: &str) -> i64 {
        let mut parts = date.split('-').map(|p| p.parse::<i64>().expect("a YYYY-MM-DD date"));
        let (y, m, d) = (parts.next().unwrap(), parts.next().unwrap(), parts.next().unwrap());
        assert!(parts.next().is_none() && (1..=12).contains(&m) && (1..=31).contains(&d), "{date}");
        let y = if m <= 2 { y - 1 } else { y };
        let era = y.div_euclid(400);
        let yoe = y - era * 400;
        let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146_097 + doe - 719_468
    }

    /// Each pin is a Capella block, and it was taken on or after the day of its slot, within a
    /// week: a later date would hide its real age.
    #[test]
    fn checkpoints_are_capella_blocks_taken_on_their_day() {
        assert_eq!(days_from_civil("1970-01-01"), 0);
        assert_eq!(days_from_civil("2026-11-24"), 20_781);
        let mut pinned = 0;
        for network in PULSECHAIN_NETWORKS {
            let Some(pin) = network.checkpoint else { continue };
            pinned += 1;
            let beacon = network.beacon;
            assert_eq!(beacon.fork_at_epoch(pin.slot / 32).fork, BeaconFork::Capella);
            let day = i64::try_from((beacon.genesis_time + pin.slot * 10) / 86_400).unwrap();
            let taken = days_from_civil(pin.taken);
            assert!((day..day + 7).contains(&taken), "chain {}: {}", network.chain_id, pin.taken);
        }
        assert_eq!(pinned, 1, "369 has a pin; 943 has none yet");
    }

    /// The upstream crates that cannot see this table ask
    /// `reth_chainspec::is_pulsechain_chain_id` instead. The two must agree.
    #[test]
    fn entries_match_the_upstream_chain_id_check() {
        for network in PULSECHAIN_NETWORKS {
            assert!(reth_chainspec::is_pulsechain_chain_id(network.chain_id));
        }
        for id in [1, 1337, 11_155_111, 32_382] {
            assert!(!reth_chainspec::is_pulsechain_chain_id(id));
            assert!(pulsechain_network(id).is_none());
        }
    }
}
