# Network activations

Every hardfork the Ethereum chain specs of this fork define, with its status on the networks the
Firehose reth node serves and its effect on the Firehose block. Review the entries that are new or
whose status changed at every upstream bump, and when an activation is announced between bumps.

Statuses come from the `alloy-hardforks` timestamps compiled into the release (0.4.11 for
`reth-v2.9.0-fh3.1`), checked 2026-10-29. "Not scheduled" means the fork has no timestamp in the
code: it reaches the tracer only once a later release schedules it.

| Fork | Mainnet | Sepolia | Hoodi | Effect on the Firehose block |
|------|---------|---------|-------|------------------------------|
| Frontier → Paris | Active | Active | Active (genesis) | Covered by the Firehose releases before this file existed. |
| Shanghai | Active (2023-04-12) | Active | Active (genesis) | Withdrawals are emitted as `Withdrawal` balance changes. |
| Cancun | Active (2024-03-13) | Active | Active (genesis) | Receipts carry the blob gas price; EIP-4788 beacon root system call. |
| Prague | Active (2025-05-07) | Active | Active | EIP-2935, EIP-7002, EIP-7251 system calls; EIP-7702 authorization nonce and code changes. |
| Osaka | Active (2025-12-03) | Active (2025-10-14) | Active (2025-10-28) | Traced by earlier Firehose releases; not re-reviewed for this file. |
| BPO1 | Active (2025-12-09) | Active (2025-10-21) | Active (2025-11-05) | None: blob parameters only. |
| BPO2 | Active (2026-01-07) | Active (2025-10-27) | Active (2025-11-12) | None: blob parameters only. |
| BPO3, BPO4, BPO5 | Not scheduled | Not scheduled | Not scheduled | None expected: blob parameters only. Re-check when scheduled. |
| Amsterdam | Not scheduled | Active (2026-10-06, block 11856337) | Not scheduled (unscheduled in v2.8.1) | Header gains `block_access_list_rlp` and `slot_number`; EIP-7708 native transfer logs; EIP-8037 state gas in call gas; EIP-2780 transactions included without a root frame are traced as an out-of-gas root call; EIP-8282 builder request system calls; EIP-8246 self-beneficiary SELFDESTRUCT no longer burns. Covered by the `amsterdam_*` prestate goldens and `firehose_live_tracing_amsterdam`. |
