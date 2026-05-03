# Other Changes Specification

This document specifies behavioral changes between upstream and the PulseChain fork that are **not** PulseChain chain support and **not** the MsgBoard feature. These are changes that affect RPC behavior, chain compatibility, or operational correctness and must be implemented to maintain parity with the reference implementation.

**Reference implementation:** `private-erigon-pulse` at tag `v3.0.0-RC8`.

---

## Table of Contents

1. [Gas Estimation Padding](#1-gas-estimation-padding)
2. [RPC Transaction Fee Cap](#2-rpc-transaction-fee-cap)
3. [Snapshot Downloader ChainName Fix](#3-snapshot-downloader-chainname-fix)
4. [MDBX MapSize Defaults](#4-mdbx-mapsize-defaults)

---

## 1. Gas Estimation Padding

### 1.1 Change Description

After the binary search in `eth_estimateGas` converges, add a **20% safety margin**:

```
account_gas_limit = (tracked separately from block gas limit)

// After binary search loop:
hi = hi + hi / 5
if account_gas_limit != 0 && hi > account_gas_limit:
    hi = account_gas_limit
```

### 1.2 Details

- `account_gas_limit` is captured when the account's balance-based gas affordability is calculated. It is always set to the allowance when the allowance fits in u64, regardless of whether `hi` exceeds it.
- The 20% padding (`hi / 5`) is applied unconditionally after binary search.
- The cap uses `account_gas_limit` (not block gas limit), so it never suggests more gas than the sender can afford.
- If `fee_cap == 0` (no fee specified), `account_gas_limit` stays 0 and the cap is not applied.

### 1.3 Rationale

Mitigates real-world gas underestimation issues where EVM execution during estimation differs from actual block execution due to state changes, opcode costs, or other environmental factors. Without this, dapps on PulseChain will get different `eth_estimateGas` results compared to the reference implementation.

---

## 2. RPC Transaction Fee Cap

### 2.1 Change

| Setting | Upstream Value | PulseChain Value |
|---------|---------------|-----------------|
| `RPCTxFeeCap` | 1 ether | 1,000,000 ether |

### 2.2 Rationale

The 1 ETH fee cap was too restrictive for PulseChain where the native token (PLS) has a different value scale. Raising to 1M effectively removes it as a practical barrier while maintaining a safety limit. Without this change, transactions with fees above 1 PLS would be rejected at the RPC layer.

---

## 3. Snapshot Downloader ChainName Fix

### 3.1 Change Description

The snapshot downloader setup must not completely disable snapshots when the chain name is empty or unrecognized.

**Problem:** For any chain not in the upstream known chain list, the chain name might be empty. The upstream code would completely disable the snapshot system for such chains.

**Fix:**
- Snapshot notification callbacks should only check whether the downloader client is initialized (not the chain name)
- External downloaders should work regardless of chain name
- Only the embedded downloader (which needs chain-specific torrent data) should be guarded by chain name checks

### 3.2 Rationale

Without this fix, PulseChain nodes cannot use the snapshot system for fast sync, since PulseChain is not in the upstream known chain list.

---

## 4. MDBX MapSize Defaults

### 4.1 Change

| Database | Upstream MapSize | PulseChain MapSize |
|----------|-----------------|-------------------|
| Diagnostics DB | 16 GB | 1 TB |
| Downloader DB | 16 GB | 1 TB |

### 4.2 Rationale

MDBX MapSize is a virtual address space reservation (not actual memory/disk allocation), so increasing it has no immediate resource cost. The 16 GB cap was insufficient for PulseChain's larger state and longer-running nodes.

---

## Summary: Behavioral Parity Checklist

| Change | Impact if Missing |
|--------|------------------|
| Gas estimation +20% | `eth_estimateGas` returns different values than reference nodes |
| RPCTxFeeCap 1M | Transactions with fees >1 PLS rejected at RPC layer |
| Snapshot ChainName fix | Fast sync completely broken for PulseChain |
| MDBX MapSize increase | Node crashes on large databases |
