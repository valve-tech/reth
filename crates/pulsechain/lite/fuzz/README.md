# reth-pulsechain-lite fuzz targets

cargo-fuzz (libFuzzer) targets for `reth-pulsechain-lite`. This crate has its own empty
`[workspace]`, so the root workspace ignores it. It builds the lite crate with the non-default
`fuzzing` feature, which exposes thin wrappers over crate-private parsers (`src/fuzz_api.rs`).

You need a nightly toolchain and `cargo install cargo-fuzz`. Run everything from this directory.
Keep the build output out of the repo's `target/`:

```sh
export CARGO_TARGET_DIR=$(git rev-parse --show-toplevel)/fuzz-target
cargo +nightly fuzz build
```

## Run a target

```sh
cargo +nightly fuzz run <target> -- -max_total_time=300 -rss_limit_mb=2048 -timeout=10
```

The corpus goes to `corpus/<target>/`, a crash to `artifacts/<target>/`. Both are git-ignored.
To replay one input: `cargo +nightly fuzz run <target> artifacts/<target>/<file>`.

**`rpc_body` must run without AddressSanitizer.** The evm2 interpreter faults (SEGV at a
near-null address) on every interpreted call in an ASAN build. Without ASAN, the same inputs
run clean, and so do the stable tests. Run it with `-s none`:

```sh
cargo +nightly fuzz run -s none rpc_body -- -max_total_time=300 -rss_limit_mb=2048 -timeout=10
```

Give `beacon_sse` its dictionary and room for long inputs: `-dict=beacon_sse.dict -max_len=20000`.

Set `LITE_FUZZ_DEBUG=1` to make `rpc_body` and `beacon_block_json` print the body they parse.

## Targets

Each target asserts invariants, not only "no panic".

| Target | What goes in | What must hold |
| --- | --- | --- |
| `beacon_block_json` | Raw bytes as a `blocks/{id}` body; or a valid block built here (Shanghai, Cancun or Prague, with transactions, withdrawals and requests), with optional byte edits to its JSON | The bounded `Shape` parse drops nothing `parse_beacon_block` reads: where a full `serde_json` parse succeeds, both give the same outcome. (It skips unnamed fields without validating them, so invalid UTF-8 there is accepted.) A parsed block's hash is its header's hash and the payload's `block_hash`, and its body matches the header. An unedited built block parses to exactly the header and body built, and is refused under any other fork. An edited one can only parse to that same block. |
| `beacon_sse` | Bytes, optionally repeated past the 64 KiB event cap, delivered as one chunk, at fuzz-chosen cuts, and one byte at a time | All three deliveries read the same events, and they match a whole-text model of the stream. |
| `wire_responses` | `snap/1` frames and eth/68 messages from raw bytes; then `P2pFetcher` account, slot, code and receipt fetches against a small world, with each peer answer raw, honest with edits, under a wrong id, a timeout or a disconnect | What decodes re-encodes to the same message. A returned account or receipt list is the true one. The store only receives nodes of the true trie, and code that hashes to a requested hash. A code fetch that passes holds every requested code. |
| `proofs` | Valid account and storage proofs (present and absent keys) of a small trie, with byte flips, dropped, duplicated, swapped, truncated, replaced and foreign nodes, and changed claims; raw node lists; edited full storage sets | `verify_account`, `verify_storage` and `verify_full_storage` only ever accept the true value. Every node they return is in the true trie, keyed by its hash. |
| `rpc_body` | Raw bytes, or JSON-RPC requests and batches built from served and unknown methods and typed params, on an empty or a four-block chain, in each `--state.on-miss` mode, with a large or a small response budget | Each reply is JSON-RPC 2.0 of the shape the body asks for: one reply per non-notification request, in order, each with the request's id and exactly one of result or error. The response budget the reply holds is all that is missing from it. |
| `config_parsers` | Arbitrary strings; sizes and durations built from a number and a unit; URL files of blank, comment, URL and arbitrary lines | Each size flag reads text as pulse-reth's `parse_byte_size`, which agrees with a reference parser of the README grammar. Each duration flag reads text as `humantime::parse_duration`. Built values round-trip (refused only on overflow). A URL file parses in order or is refused naming a kept line, never echoing the file. Every accepted URL is https or loopback, with no fragment. |
