//! `PulseChain` chainspec statics.
//!
//! Both PULSECHAIN and `PULSECHAIN_TESTNET_V4` reuse the Ethereum mainnet genesis
//! (identical hash: 0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3).
//! No custom genesis JSON is needed — we clone `MAINNET` and override the
//! chain-specific fields.

use std::sync::{Arc, LazyLock};

use alloy_eips::eip7892::BlobScheduleBlobParams;
use alloy_primitives::{address, b256, Address, B256};
use reth_chainspec::{Chain, ChainSpec, DepositContract, MAINNET};
use reth_network_peers::NodeRecord;

use crate::hardfork::{
    PulsechainHardfork, PRIMORDIAL_PULSE_MAINNET_BLOCK, PRIMORDIAL_PULSE_TESTNET_V4_BLOCK,
    PULSECHAIN_PARIS_TTD, SHANGHAI_MAINNET_TIMESTAMP, SHANGHAI_TESTNET_V4_TIMESTAMP,
};

/// `PulseChain` mainnet chain ID.
pub const PULSECHAIN_MAINNET_CHAIN_ID: u64 = 369;

/// `PulseChain` testnet v4 chain ID.
pub const PULSECHAIN_TESTNET_V4_CHAIN_ID: u64 = 943;

/// `PulseChain` mainnet deposit contract address.
/// Deployed during `PrimordialPulse` at block 17,233,000.
pub const PULSECHAIN_DEPOSIT_CONTRACT: Address =
    address!("3693693693693693693693693693693693693693");

/// Ethereum deposit contract address — destroyed during `PrimordialPulse`.
pub const ETH_DEPOSIT_CONTRACT: Address = address!("00000000219ab540356cBB839Cbe05303d7705Fa");

/// keccak256("DepositEvent(bytes,bytes,bytes,bytes,bytes)") — the same ABI signature
/// used by both the Ethereum and `PulseChain` deposit contracts.
const DEPOSIT_EVENT_TOPIC: B256 =
    b256!("649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c5");

/// `PulseChain` mainnet chain spec.
///
/// Identical genesis to Ethereum mainnet (same allocation, same block hash).
/// Chain-specific overrides: chain ID 369, `PrimordialPulse` at block 17,233,000,
/// Shanghai at timestamp 1,683,786,515, no Cancun/Prague/blob upgrades.
pub static PULSECHAIN: LazyLock<Arc<ChainSpec>> = LazyLock::new(|| {
    let hardforks = PulsechainHardfork::mainnet();
    let mut spec = (**MAINNET).clone();
    spec.chain = Chain::from_id(PULSECHAIN_MAINNET_CHAIN_ID);
    spec.hardforks = hardforks;
    // The PrimordialPulse block is the last PoW block. Paris (PoS) starts one block later.
    spec.paris_block_and_final_difficulty =
        Some((PRIMORDIAL_PULSE_MAINNET_BLOCK + 1, PULSECHAIN_PARIS_TTD));
    spec.deposit_contract = Some(DepositContract::new(
        PULSECHAIN_DEPOSIT_CONTRACT,
        PRIMORDIAL_PULSE_MAINNET_BLOCK,
        DEPOSIT_EVENT_TOPIC,
    ));
    // PulseChain only goes to Shanghai — no blob transactions, no upgrade schedule.
    spec.blob_params = BlobScheduleBlobParams::default();

    // Sync genesis.config to match PulseChain parameters. The hardforks field
    // is authoritative for runtime decisions; genesis.config is used for
    // serialization (e.g., `reth dump-genesis`).
    spec.genesis.config.chain_id = PULSECHAIN_MAINNET_CHAIN_ID;
    spec.genesis.config.shanghai_time = Some(SHANGHAI_MAINNET_TIMESTAMP);
    spec.genesis.config.cancun_time = None;
    spec.genesis.config.prague_time = None;
    spec.genesis.config.osaka_time = None;
    spec.genesis.config.terminal_total_difficulty = Some(PULSECHAIN_PARIS_TTD);

    Arc::new(spec)
});

/// `PulseChain` testnet v4 chain spec (chain ID 943).
///
/// Same genesis as mainnet (`PulseChain` testnet v4 also starts from Ethereum mainnet genesis).
/// `PrimordialPulse` fires at block 16,492,700; Shanghai at timestamp 1,682,700,369.
pub static PULSECHAIN_TESTNET_V4: LazyLock<Arc<ChainSpec>> = LazyLock::new(|| {
    let hardforks = PulsechainHardfork::testnet_v4();
    let mut spec = (**MAINNET).clone();
    spec.chain = Chain::from_id(PULSECHAIN_TESTNET_V4_CHAIN_ID);
    spec.hardforks = hardforks;
    // The PrimordialPulse block is the last PoW block. Paris (PoS) starts one block later.
    spec.paris_block_and_final_difficulty =
        Some((PRIMORDIAL_PULSE_TESTNET_V4_BLOCK + 1, PULSECHAIN_PARIS_TTD));
    spec.deposit_contract = Some(DepositContract::new(
        PULSECHAIN_DEPOSIT_CONTRACT,
        PRIMORDIAL_PULSE_TESTNET_V4_BLOCK,
        DEPOSIT_EVENT_TOPIC,
    ));
    spec.blob_params = BlobScheduleBlobParams::default();

    spec.genesis.config.chain_id = PULSECHAIN_TESTNET_V4_CHAIN_ID;
    spec.genesis.config.shanghai_time = Some(SHANGHAI_TESTNET_V4_TIMESTAMP);
    spec.genesis.config.cancun_time = None;
    spec.genesis.config.prague_time = None;
    spec.genesis.config.osaka_time = None;
    spec.genesis.config.terminal_total_difficulty = Some(PULSECHAIN_PARIS_TTD);

    Arc::new(spec)
});

/// Returns the chain ID for `PulseChain` mainnet.
pub const fn pulsechain_mainnet() -> u64 {
    PULSECHAIN_MAINNET_CHAIN_ID
}

/// Returns the chain ID for `PulseChain` testnet v4.
pub const fn pulsechain_testnet_v4() -> u64 {
    PULSECHAIN_TESTNET_V4_CHAIN_ID
}

/// Returns the chain ID in effect at a given block number for `PulseChain` mainnet.
///
/// Before `PrimordialPulse`: returns 1 (Ethereum mainnet chain ID, for history replay).
/// At and after `PrimordialPulse`: returns 369.
///
/// `PulseChain` replays Ethereum history, so the CHAINID opcode must return 1 on
/// blocks where Ethereum contracts were originally deployed (chain ID 1 contracts
/// expecting to run on chain 1 would break if CHAINID returned 369).
pub const fn chain_id_at_block_mainnet(block: u64) -> u64 {
    if block < PRIMORDIAL_PULSE_MAINNET_BLOCK {
        1
    } else {
        PULSECHAIN_MAINNET_CHAIN_ID
    }
}

/// Returns the chain ID in effect at a given block number for `PulseChain` testnet v4.
///
/// Before `PrimordialPulse`: returns 1.
/// At and after `PrimordialPulse`: returns 943.
pub const fn chain_id_at_block_testnet_v4(block: u64) -> u64 {
    if block < PRIMORDIAL_PULSE_TESTNET_V4_BLOCK {
        1
    } else {
        PULSECHAIN_TESTNET_V4_CHAIN_ID
    }
}

// ---------------------------------------------------------------------------
// Bootnodes
// ---------------------------------------------------------------------------

/// `PulseChain` mainnet bootnodes.
///
/// Source: <https://gitlab.com/pulsechaincom/private-erigon-pulse/-/blob/main/params/bootnodes.go>
pub static PULSECHAIN_BOOTNODES: [&str; 10] = [
    "enode://bdb96e7ff6607414a4be8cdc8458861e9c22a25a0c254c7bb9c9c8423912e998b59e7ba012801538480eb78cec4d6766ab0b379d0b60356de84a7cdaec988c0b@5.9.124.244:30303",     // bootnode-001-hetzner-fsn
    "enode://d69f8d28804ab34f7d5e20ac8bd4940412602787e2c37fc3600adc60dcd5d0a52e1fe1baccbefb6e278e1ee59fcb099c45db242edeb5e0a4547ff971218a0592@148.251.54.222:30303",  // bootnode-002-hetzner-fsn
    "enode://1c9e030aa44b95b8239e1c97926787e12770c015b9dbf7a89b1178a5f4fab02462fde3489662119872dad5998e23440f78daae753d7a8f800900d871f08650a4@65.108.236.231:30303",  // bootnode-003-hetzner-hel
    "enode://95097eaeda4118297ad0ccb6160e1c9188af7560d25b4724052e0f004a33aaddb0e468103d622c77539b692fd1d9f3c156cb76c9ea402a86e3170d6ae60092e7@135.181.212.228:30303", // bootnode-004-hetzner-hel
    "enode://da30ab2475cda64c2454b659a3ef045884c7d02b97d524d710020fdc2f37192b0aac7992bca8b7afd57474eb477e95567c8e0fe98003b779834f265304376c3c@135.181.229.180:30303", // g4mm4-bootnode-001
    "enode://01d93871155cbe270bc60acfebc1aa859aacce002acaac39d633aa8e7c186ee26d19a41a50d8bc094c025a546ae5e1a38dc21ead75b4e7ddf4e917988d2f7c74@46.4.224.159:30303",    // g4mm4-bootnode-002
    "enode://96367e5e533cde68b6d3e7cc5308901fb1e4b1df51d2a0442df365fcfb8ba27a6e8bcde44b3629579da9e13d819f6059386a1e81ea4c5fd10d14599639c16214@46.4.224.160:30303",    // g4mm4-bootnode-003
    "enode://aece632270d66ff6bf9e9528e766b5829fb3b7812d48e4934c2768c45976b5f98559ce6d5763dc16d4351b15e776b55e2b983a0c367bdbe6279cfb3242f2587e@95.217.148.233:30303",  // g4mm4-bootnode-004
    "enode://95e1761e526d77fc732416a31c9c1795863b557ea02880101c01d14d13fdabb9312ce45c4f3037ad88002815f6826a36d86e42a1a7122f9188c64f53c4b68b1e@148.251.185.52:30303",  // g4mm4-bootnode-005
    "enode://0ad3bc059105b0cbc1d30a330f79b4fd4ef40f37782194daa6d3412a29a69e0190dd246fc019be9157a4bf095b584ab7874beba4c71c02156f602f32ff389f00@138.201.220.52:30303",  // g4mm4-bootnode-006
];

/// `PulseChain` Testnet V4 bootnodes.
///
/// Source: <https://gitlab.com/pulsechaincom/private-erigon-pulse/-/blob/main/params/bootnodes.go>
pub static PULSECHAIN_TESTNET_V4_BOOTNODES: [&str; 8] = [
    "enode://3edb6b2b76ef50af30d3b02e098f00546f1a460ff1c82adad2639a57f6742c69516d24d760c0dd4555334adb01e6f3327f1a61056b3d89db4de10060248e8dea@65.21.204.190:30303",   // bootnode-001-hetzner-hel
    "enode://2b9af9cc9d09e2d2ef8cb3203f859e69b0175c1d7c41e14acf5162b239a773a966eea98a71999af9424ddb5b27a44759318869f8a4ba954483889aafdd6ea921@157.90.129.118:30303",  // bootnode-002-hetzner-fsn
    "enode://2181f1b061713260eb806a7824d880088bbf3b47cf60fa7bc610439aedd20c213479df83a6eeaf42b41ad6f3eac6973ddc1d8d903a00094603ad667d5d87161f@37.27.57.158:30303",    // g4mm4-bootnode-001
    "enode://c1a8bc7b4a7fa66e3eed6732d966f98de6b4e4243353e9c2f4d632126b8da73022b3becf1582e940d3feeaf3243f63304356856053c76a7ea6cc5c50ad21d483@213.133.100.132:30303", // g4mm4-bootnode-002
    "enode://7dce6f27d102ae4fac47042b0ed8fadfce0037a5384ae171017b8b6684efe57bb850359e00582a6f8099ac60b41e16efe46afb8772270e5e1cad3f7ed79d0e41@85.10.193.180:30303",   // g4mm4-bootnode-003
    "enode://94eedc89cebf735374bbae8078fff23744d7b118af6c0f33804d1ccf6cc8fdb9db7f55ccf81455034bc34b43f00fdc7ea5693b86d6c6098fc9603f689d0d1fca@95.217.150.118:30303",  // g4mm4-bootnode-004
    "enode://5999295986a65151d416dc09635da46896e8cd5e2f0dda0823ed3a0981dc50885407e5a990aa34e165c345e7bebaa837fcf9afaaa5e62d5add1fed6d4c9edbcc@95.217.148.234:30303",  // g4mm4-bootnode-005
    "enode://86831392545cec45fa30b578717684c4ffcf2e2bf050d4ecfdd5b9a6b2136e10d58f8606bacdd137e6ce68c1081442e39347ed391f166366f4951ab031156e93@138.201.193.233:30303", // g4mm4-bootnode-006
];

/// Returns parsed `PulseChain` mainnet boot nodes.
pub fn pulsechain_nodes() -> Vec<NodeRecord> {
    parse_nodes(&PULSECHAIN_BOOTNODES[..])
}

/// Returns parsed `PulseChain` Testnet V4 boot nodes.
pub fn pulsechain_testnet_v4_nodes() -> Vec<NodeRecord> {
    parse_nodes(&PULSECHAIN_TESTNET_V4_BOOTNODES[..])
}

// ---------------------------------------------------------------------------
// DNS discovery
// ---------------------------------------------------------------------------

/// DNS discovery `enrtree` URL for `PulseChain` mainnet (chain ID 369).
///
/// Source: go-pulse `params/bootnodes.go` `KnownDNSNetwork()`
pub const PULSECHAIN_DNS_NETWORK: &str =
    "enrtree://APFXO36RU3TWV7XFGWI2TYF5IDA3WM2GPTRL3TCZINWHZX4R6TAOK@all.mainnet.pulsedisco.net";

/// DNS discovery `enrtree` URL for `PulseChain` Testnet V4 (chain ID 943).
///
/// Source: go-pulse `params/bootnodes.go` `KnownDNSNetwork()`
pub const PULSECHAIN_TESTNET_V4_DNS_NETWORK: &str =
    "enrtree://APFXO36RU3TWV7XFGWI2TYF5IDA3WM2GPTRL3TCZINWHZX4R6TAOK@all.testnet-v4.pulsedisco.net";

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn parse_nodes(nodes: &[&str]) -> Vec<NodeRecord> {
    nodes.iter().map(|s| s.parse().expect("valid enode URI")).collect()
}
