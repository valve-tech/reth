# Vendored alloy-rpc-types-eth

This is the crates.io source of `alloy-rpc-types-eth` 2.5.0, unchanged except for
`src/state.rs`. There, the `state` and `stateDiff` maps of `AccountOverride` accept keys and values
of 1 to 64 hex digits and left-pad them to 32 bytes (module `storage_words`). PulseChain's
erigon 2.4.1 requires short values such as `0x2a`; the spec, geth and current erigon use 32-byte
words. Padded input parses as before, and serialization still writes 32-byte words.

The same change is on branch `valve/v2.5.0` of https://github.com/valve-tech/alloy (aa2279095a).

At every alloy bump: copy the new crates.io source here, reapply the `state.rs` change, keep the
patch in `[patch.crates-io]` of the root `Cargo.toml`, check that `Cargo.lock` has no
`patch.unused`, and run the e2e test `test_state_override_accepts_short_storage_words`.

Remove this crate once eRPC's `requestFormat: canonical` rewrite (or an upstream alloy change)
covers every caller.
