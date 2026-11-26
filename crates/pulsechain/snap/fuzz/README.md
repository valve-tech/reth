# reth-pulsechain-snap fuzz targets

cargo-fuzz (libFuzzer) targets for the `snap/1` decoder and request serving. This crate has its own empty `[workspace]`, so the root workspace ignores it. It copies the root's `[patch]` sections and starts from the root `Cargo.lock`, so it builds the same dependency tree. When the root patches change, copy them here too.

The targets use the `fuzzing` feature of `reth-pulsechain-snap`. That feature exposes `fuzz_api`, which holds the in-memory test state and a few private helpers.

## Targets

- `snap1_decode`: arbitrary bytes into `Snap1Message::decode`, the decoder the connection runs on each frame. A message that decodes must encode and decode back to itself. A decoded request must be canonical. A frame cut by one byte, or with one extra byte, must not decode. A `GetTrieNodes` must keep at most the serving caps of sets and lookups. It must also equal a plain derived decode, cut to what serving reads, wherever the plain decode succeeds. Each input is also read as the parts of a `GetTrieNodes` frame with repeated sets, so frames past the 1024-set cap occur.
- `snap1_serve`: a structured state (accounts, storage, code) and up to four `GetAccountRange`, `GetStorageRanges`, `GetTrieNodes` and `GetByteCodes` requests. The requests have arbitrary roots, origins, limits, path sets and byte budgets. A reply must stay within its reply budget plus `REPLY_SLACK`. The items before the last one must fit in the serving budget, and the item caps must hold. Ranges must be the run of the state from the origin. A range proof must verify the origin and the last key against the root. The verifier must reject that proof's path after any one byte changes. Trie nodes must be the nodes at exactly the requested paths. Serving the decoded wire request must give the same reply as serving the full request.

## Run

```sh
cd crates/pulsechain/snap/fuzz
export CARGO_TARGET_DIR="$PWD/../../../../fuzz-target"
cargo +nightly fuzz run -O snap1_decode -- -max_total_time=300 -rss_limit_mb=2048 -timeout=10
cargo +nightly fuzz run -O snap1_serve  -- -max_total_time=300 -rss_limit_mb=2048 -timeout=10
```

Crashes go to `artifacts/<target>/`, and the corpus grows in `corpus/<target>/`. Git ignores both directories. To replay a crash, run `cargo +nightly fuzz run -O <target> artifacts/<target>/crash-...`. To print a `snap1_serve` input as its structured value, run `cargo +nightly fuzz fmt -O snap1_serve <file>`.

On a 2026 Apple-silicon machine with ASan, `snap1_decode` runs about 36,000 execs/s on raw bytes only, and about 2,600 execs/s with the built frames. `snap1_serve` runs about 1,000 to 1,500 execs/s.
