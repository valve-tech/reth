//! The `PulseChain` beacon light-client protocol, shared by `reth-lite` and the light-client data
//! server.
//!
//! It has no I/O: callers fetch the bytes and hand them in. [`sync_committee`] holds the types,
//! their SSZ form, the Merkle checks and [`sync_committee::LightClientStore`]. [`json`] reads and
//! writes the beacon API's JSON form of the light-client answers. [`ssz_merkle`] hashes serialized
//! SSZ in place, and [`capella`] gives it the `BeaconState` and `SignedBeaconBlock` schemas.
//! [`derive`] builds the light-client answers from serialized blocks and states. [`checkpoint`]
//! holds the trusted roots a first store starts from, and the bootstraps that ship at the pins.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

pub mod capella;
pub mod checkpoint;
pub mod derive;
pub mod json;
pub mod ssz_merkle;
pub mod sync_committee;
