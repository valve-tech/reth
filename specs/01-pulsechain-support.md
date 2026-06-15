# PulseChain Support Specification

This document specifies all changes required to add PulseChain and PulseChain Testnet-V4 support to an Ethereum execution/consensus client. The reference implementation is `private-erigon-pulse` at tag `v3.0.0-RC8`.

**Scope:** Everything needed to go from Ethereum-only to Ethereum + PulseChain + PulseChainV4.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Chain Identity](#2-chain-identity)
3. [Chain Configuration](#3-chain-configuration)
4. [PrimordialPulse Fork Mechanism](#4-primordialpulse-fork-mechanism)
5. [Sacrifice Credits](#5-sacrifice-credits)
6. [Deposit Contract Replacement](#6-deposit-contract-replacement)
7. [Consensus Changes (Execution Layer)](#7-consensus-changes-execution-layer)
8. [Transaction Signing and Validation](#8-transaction-signing-and-validation)
9. [Consensus Layer (Beacon Chain / Caplin)](#9-consensus-layer-beacon-chain--caplin)
10. [Reward Burn](#10-reward-burn)
11. [Snapshot and Downloader Support](#11-snapshot-and-downloader-support)
12. [DNS Discovery](#12-dns-discovery)
13. [Gas Estimation](#13-gas-estimation)
14. [Engine API Adjustments](#14-engine-api-adjustments)
15. [Detection Mechanisms Summary](#15-detection-mechanisms-summary)

---

## 1. Overview

PulseChain is a fork of the Ethereum mainnet state. It shares Ethereum's genesis block and all history up to a specific block called `PrimordialPulseBlock`. At that block, the chain diverges by:

1. Applying sacrifice credits (balance allocations to addresses)
2. Replacing the Ethereum deposit contract with a PulseChain deposit contract
3. Triggering a PoW-to-PoS merge transition via a trivial difficulty value
4. Switching the effective chain ID for transaction signing

After the fork, PulseChain operates as an independent PoS chain with its own beacon chain, validators, and configuration.

### Networks

| Network | Chain ID | PrimordialPulseBlock | TTD |
|---------|----------|---------------------|-----|
| PulseChain Mainnet | 369 | 17,233,000 | 58,750,003,716,598,352,947,541 |
| PulseChain Testnet-V4 | 943 | 16,492,700 | 58,750,003,716,598,352,947,541 |
| PulseChain Devnet | 32,382 | 10 | 393,216 |

---

## 2. Chain Identity

### 2.1 Network IDs

Add the following constants:

```
PulseChainChainID       = 369
PulseChainTestnetV4ChainID = 943
```

Both must be added to the "all networks" list and the networkID-to-name mapping.

### 2.2 Network Names

```
PulseChain           = "pulsechain"
PulseChainDevnet     = "pulsechain-devnet"
PulseChainTestnetV4  = "pulsechain-testnet-v4"
```

### 2.3 Data Directories

PulseChain and PulseChainTestnetV4 get their own default data directory names: `pulsechain` and `pulsechain-testnet-v4` (following the same pattern as `sepolia`, `holesky`, etc.).

### 2.4 Genesis Hashes

PulseChain mainnet and testnet share the Ethereum mainnet genesis hash because they fork from Ethereum's state:

```
PulseChainGenesisHash         = 0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3
PulseChainTestnetGenesisHash  = 0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3
PulseChainDevnetGenesisHash   = 0xdbc883fdd1357c5340e4bb624a3dd9af4788602a23af0a42080b31a382c9fba8
```

### 2.5 Version String

The client version string should include a variant identifier. Pattern: `{major}.{minor}.{micro}-{variant}-{modifier}`, e.g., `3.0.0-pulse-RC8`.

---

## 3. Chain Configuration

### 3.1 Config Struct Extensions

Add the following fields to the chain config:

```
PrimordialPulseBlock  integer (optional)          // Block number where PulseChain fork activates (null = not a PulseChain fork)
PulseChain            PulseChainConfig (optional)  // PulseChain-specific configuration (null = Ethereum chain)
```

### 3.2 PulseChainConfig

```
PulseChainConfig:
    Treasury  PulseChainTreasury (optional)  // Optional treasury allocation at fork block

PulseChainTreasury:
    Addr      string  // Hex address of treasury
    Balance   string  // Hex balance to allocate
```

### 3.3 PulseChainTTDOffset

```
PulseChainTTDOffset = 131,072  (0x20000)
```

This is the trivial difficulty value returned at the PrimordialPulse block to trigger the merge.

### 3.4 Chain Specification Files

#### PulseChain Mainnet (`pulsechain.json`)

```json
{
    "chainId": 369,
    "homesteadBlock": 1150000,
    "daoForkBlock": 1920000,
    "daoForkSupport": true,
    "eip150Block": 2463000,
    "eip155Block": 2675000,
    "byzantiumBlock": 4370000,
    "constantinopleBlock": 7280000,
    "petersburgBlock": 7280000,
    "istanbulBlock": 9069000,
    "muirGlacierBlock": 9200000,
    "berlinBlock": 12244000,
    "londonBlock": 12965000,
    "arrowGlacierBlock": 13773000,
    "grayGlacierBlock": 15050000,
    "terminalTotalDifficulty": 58750003716598352947541,
    "terminalTotalDifficultyPassed": true,
    "shanghaiTime": 1683786515,
    "primordialPulseBlock": 17233000,
    "pulseChain": {}
}
```

#### PulseChain Testnet-V4 (`pulsechain-testnet-v4.json`)

```json
{
    "chainId": 943,
    "homesteadBlock": 1150000,
    "daoForkBlock": 1920000,
    "daoForkSupport": true,
    "eip150Block": 2463000,
    "eip155Block": 2675000,
    "byzantiumBlock": 4370000,
    "constantinopleBlock": 7280000,
    "petersburgBlock": 7280000,
    "istanbulBlock": 9069000,
    "muirGlacierBlock": 9200000,
    "berlinBlock": 12244000,
    "londonBlock": 12965000,
    "arrowGlacierBlock": 13773000,
    "grayGlacierBlock": 15050000,
    "terminalTotalDifficulty": 58750003716598352947541,
    "terminalTotalDifficultyPassed": true,
    "shanghaiTime": 1682700369,
    "primordialPulseBlock": 16492700,
    "pulseChain": {
        "treasury": {
            "addr": "0xA592ED65885bcbCeb30442F4902a0D1Cf3AcB8fC",
            "balance": "0x314DC6448D9338C15B0A00000000"
        }
    }
}
```

#### PulseChain Devnet (`pulsechain-devnet.json`)

```json
{
    "chainId": 32382,
    "homesteadBlock": 0,
    "eip150Block": 0,
    "eip155Block": 0,
    "byzantiumBlock": 0,
    "constantinopleBlock": 0,
    "petersburgBlock": 0,
    "istanbulBlock": 0,
    "berlinBlock": 0,
    "londonBlock": 0,
    "terminalTotalDifficulty": 393216,
    "terminalTotalDifficultyPassed": true,
    "shanghaiTime": 0,
    "primordialPulseBlock": 10,
    "pulseChain": {
        "treasury": {
            "addr": "0x123463a4b065722e99115d6c222f267d9cabb524",
            "balance": "0xC9F2C9CD04674EDEA40000000"
        }
    }
}
```

### 3.5 Config Helper Methods

```
IsPrimordialPulseBlock(num: u64) -> bool
    Returns true if PrimordialPulseBlock is set AND num exactly equals it.

PrimordialPulseAhead(num: u64) -> bool
    Returns true if PrimordialPulseBlock is set AND is strictly greater than num.
    This means we are still in the pre-fork (Ethereum) portion of the chain.
```

### 3.6 Genesis Block Constructors

Three new genesis constructors:

- **PulseChainGenesisBlock()** — Uses Ethereum mainnet allocs, PulseChain config. Same genesis params as Ethereum (nonce 0x42, gasLimit 5000, difficulty 0x20000, alloc from mainnet).
- **PulseChainTestnetV4GenesisBlock()** — Same as mainnet.
- **PulseChainDevnetGenesisBlock()** — Uses `pulsechain-devnet.json` allocs, gasLimit 30,000,000, difficulty 131072.

### 3.7 Config Resolution by Chain ID

Because PulseChain shares Ethereum's genesis hash, config resolution cannot rely solely on genesis hash. When resolving the config, use chain ID as the primary selector for PulseChain networks:

```
if chainId == 369:  return PulseChainConfig
if chainId == 943:  return PulseChainTestnetV4Config
else: return configByGenesisHash(genesisHash)
```

---

## 4. PrimordialPulse Fork Mechanism

### 4.1 Difficulty Override

In the difficulty calculation function (`CalcDifficulty`), add a highest-priority case:

```
if config.IsPrimordialPulseBlock(nextBlockNumber):
    return PulseChainTTDOffset  // 131,072
```

This causes the total difficulty at the PrimordialPulse block to exceed the chain's TTD, triggering the PoW-to-PoS merge transition for PulseChain's own beacon chain.

### 4.2 Fork Actions at PrimordialPulseBlock

During block finalization (`Finalize`), when `IsPrimordialPulseBlock(header.Number)` is true, execute:

```
PrimordialPulseFork(state, config.PulseChain, config.ChainID)
```

This function performs two actions in order:
1. Apply sacrifice credits
2. Replace the deposit contract

### 4.3 Pre-Fork Chain ID Handling

For blocks before PrimordialPulseBlock (`PrimordialPulseAhead(num)` returns true):

- **Chain rules:** Use Ethereum mainnet chain ID (`1`) instead of PulseChain chain ID
- **Shanghai check:** Use the hardcoded Ethereum mainnet Shanghai timestamp (`1681338455`) instead of the chain's configured `shanghaiTime`
- **EIP-155 compatibility:** Allow mismatching chain IDs in config compatibility checks (because the chain transitions from ID 1 to 369/943)

### 4.4 Merge Verification

When verifying block headers in the merge consensus engine, add a PulseChain guard:

If the TTD has not been reached yet AND `config.PulseChain != nil`, only delegate to ethash verification if the header is not a PoS header (`!IsPoSHeader(header)`). Without this, PulseChain PoS blocks arriving before the client locally computes TTD-reached would be incorrectly rejected.

---

## 5. Sacrifice Credits

### 5.1 Binary Data Format

Sacrifice credits are stored in binary files containing compressed allocation data:

- `sacrifice_credits_mainnet.bin` — for chain ID 369
- `sacrifice_credits_testnet_v4.bin` — for chain ID 943

Source: `https://gitlab.com/pulsechaincom/compressed-allocations`

### 5.2 Algorithm

```
function applySacrificeCredits(state, pulseChainConfig, chainID):
    # 1. Select binary based on chain ID
    if chainID == 369:
        data = sacrifice_credits_mainnet.bin
    else if chainID == 943:
        data = sacrifice_credits_testnet_v4.bin
    else:
        return  # no credits for unknown chains

    # 2. Apply treasury allocation if configured
    if pulseChainConfig.Treasury != nil:
        addr = parseAddress(pulseChainConfig.Treasury.Addr)
        balance = parseBigInt(pulseChainConfig.Treasury.Balance)  # hex string
        state.AddBalance(addr, balance, BalanceIncreaseSacrificeCredit)

    # 3. Parse and apply credit records
    reader = newReader(data)
    while reader.hasMore():
        byteCount = reader.readByte()       # 1 byte: length of following record
        record = reader.readBytes(byteCount) # byteCount bytes
        address = record[0:20]               # first 20 bytes = address
        balance = bigIntFromBytes(record[20:]) # remaining bytes = balance (big-endian)
        state.AddBalance(address, balance, BalanceIncreaseSacrificeCredit)
```

### 5.3 Balance Change Reason

Add a new balance change reason constant:

```
BalanceIncreaseSacrificeCredit = 15
```

---

## 6. Deposit Contract Replacement

### 6.1 Addresses

```
EthereumDepositContract  = 0x00000000219ab540356cBB839Cbe05303d7705Fa
PulseChainDepositContract = 0x3693693693693693693693693693693693693693
```

### 6.2 Algorithm

At the PrimordialPulse block, after applying sacrifice credits:

```
function replaceDepositContract(state):
    # 1. Self-destruct the old Ethereum deposit contract
    state.SelfDestruct(EthereumDepositContract)

    # 2. Set a nil contract at the old address (prevents accidental PLS sends)
    state.SetCode(EthereumDepositContract, nilContractBytes)

    # 3. Deploy the PulseChain deposit contract
    state.SetBalance(PulseChainDepositContract, 0)
    state.SetCode(PulseChainDepositContract, depositContractBytes)
    state.SetNonce(PulseChainDepositContract, 0)
    state.SetIncarnation(PulseChainDepositContract, FirstContractIncarnation)

    # 4. Initialize storage slots (Merkle tree)
    for slot in range(0x22, 0x41):  # slots 0x22 through 0x40 inclusive
        state.SetState(PulseChainDepositContract, slot, merkleInitValue[slot])
```

### 6.3 Nil Contract Bytecode

The nil contract at the old deposit address is a compiled Solidity contract with no receive/fallback function, preventing accidental value transfers:

```
0x6080604052600080fdfea2646970667358221220d10eb20cd2b73b968672d3bce97dff1eb0797edc10179828d6039dc6b4eda2fe64736f6c634300060b0033
```

### 6.4 Deposit Contract Bytecode and Storage

The full deposit contract bytecode and Merkle initialization values are embedded as byte constants. The exact values are embedded as byte constants in the implementation.

---

## 7. Consensus Changes (Execution Layer)

### 7.1 IsShanghai Signature Change

The `IsShanghai` check must be expanded to take both block number and timestamp:

```
IsShanghai(block_number: u64, timestamp: u64) -> bool
```

For PulseChain pre-fork blocks (`PrimordialPulseAhead(blockNumber)`), use Ethereum mainnet's Shanghai timestamp (`1681338455`) instead of the chain's configured value. This ensures pre-fork blocks are validated with Ethereum mainnet rules.

All callers of `IsShanghai` must be updated to pass block number (engine API, merge consensus, t8ntool).

### 7.2 TTD Estimation Guard

In header download TTD estimation, add a guard against division by zero when `lastDifficulty == 0`:

```
if lastDifficulty != 0:
    estimatedBlocksToTTD = remainingDifficulty / lastDifficulty
```

### 7.3 EVM Skip Analysis

PulseChain and PulseChainTestnetV4 reuse the same EVM analysis skip blocks as Ethereum mainnet (known blocks that can skip EVM code analysis for performance).

### 7.4 Block Finalization (Reward Burn on EL)

In `Finalize()`, when applying PulseChain burn to block rewards: see the consensus ethash code. The PulseChain burn on the EL side is applied via `ApplyBurn` to block rewards with the formula:

```
reward * secondsPerSlot / 12 * 3 / 4
```

Only applies when `config.PulseChain != nil`. See Section 10 for full burn specification.

---

## 8. Transaction Signing and Validation

### 8.1 MakeSigner Pre-Fork Override

In `MakeSigner()`, when `PrimordialPulseAhead(blockNumber)` is true, force the chain ID to `1` (Ethereum mainnet). This is required because pre-fork blocks contain transactions signed with Ethereum's chain ID.

### 8.2 Transaction Pool Legacy TX Support

Add a `allowPulseChainLegacy` flag to the transaction parser context:

```
NewTxnParseContext(chainID, allowPulseChainLegacy bool)
```

When parsing legacy transactions where the chain ID in the signature doesn't match the configured chain ID:

- If `allowPulseChainLegacy` is false: reject the transaction
- If `allowPulseChainLegacy` is true: accept only if the transaction's chain ID is `1` (Ethereum mainnet)

This allows PulseChain to process pre-fork Ethereum transactions (signed with chainID=1) alongside post-fork PulseChain transactions (signed with chainID=369/943).

Set `allowPulseChainLegacy = (chainConfig.PulseChain != nil)` when building snapshots from historical data. In the live transaction pool, use `false`.

---

## 9. Consensus Layer (Beacon Chain / Caplin)

### 9.1 Network Types

```
PulseChainNetwork         = 369
PulseChainTestnetV4Network = 943
```

### 9.2 PulseChain Beacon Config (Mainnet)

| Parameter | Value | Ethereum Default |
|-----------|-------|-----------------|
| PresetBase | `"pulsechain"` | `"mainnet"` |
| ConfigName | `"pulsechain"` | `"mainnet"` |
| BaseRewardFactor | 64,000 | 64 |
| EffectiveBalanceIncrement | 1,000,000,000,000,000 (1e15) | 1,000,000,000 (1e9) |
| MaxEffectiveBalance | 32,000,000,000,000,000 (32e15) | 32,000,000,000 (32e9) |
| TerminalTotalDifficulty | 58,750,003,716,598,352,947,541 | same |
| MinGenesisActiveValidatorCount | 4,096 | 16,384 |
| MinGenesisTime | 1,683,776,400 | 1,606,824,000 |
| GenesisForkVersion | 0x00000369 | 0x00000000 |
| GenesisDelay | 300 | 604,800 |
| AltairForkVersion | 0x0000036a | 0x01000000 |
| AltairForkEpoch | 1 | 74,240 |
| BellatrixForkVersion | 0x0000036b | 0x02000000 |
| BellatrixForkEpoch | 2 | 144,896 |
| CapellaForkVersion | 0x0000036c | 0x03000000 |
| CapellaForkEpoch | 3 | 194,048 |
| DenebForkVersion | 0x0000036d | 0x04000000 |
| DenebForkEpoch | MaxUint64 (not activated) | 269,568 |
| ElectraForkVersion | 0x0000036e | 0x05000000 |
| ElectraForkEpoch | MaxUint64 | varies |
| FuluForkVersion | 0x0000036f | 0x06000000 |
| FuluForkEpoch | MaxUint64 | varies |
| SecondsPerSlot | 10 | 12 |
| EjectionBalance | 16,000,000,000,000,000 (16e15) | 16,000,000,000 (16e9) |
| DepositChainID | 369 | 1 |
| DepositNetworkID | 369 | 1 |
| DepositContractAddress | 0x3693693693693693693693693693693693693693 | 0x00000000219ab540356cBB839Cbe05303d7705Fa |

### 9.3 PulseChain Testnet-V4 Beacon Config

Same as mainnet except:

| Parameter | Value |
|-----------|-------|
| ConfigName | `"pulsechain-testnet-v4"` |
| MinGenesisTime | 1,674,864,000 |
| GenesisForkVersion | 0x00000943 |
| AltairForkVersion | 0x00000944 |
| BellatrixForkVersion | 0x00000945 |
| CapellaForkVersion | 0x00000946 |
| CapellaForkEpoch | 4,200 |
| DenebForkVersion | 0x00000947 |
| ElectraForkVersion | 0x00000948 |
| FuluForkVersion | 0x00000949 |
| DepositChainID | 943 |
| DepositNetworkID | 943 |

### 9.4 Initial State SSZ Files

Two embedded genesis state files in SSZ format (Phase0 encoding):

- `pulsechain.state.ssz` (genesis hash root: `b0ef7e353854f154ebb8caf6649e5f8f4d51b8261635afade2014b10fb01b04e`)
- `pulsechain_testnet_v4.state.ssz` (genesis hash root: `9587ed84e249eed3008141c3fe77679ae8a4a7895cf83ae9bb5dbe9ccfd51d11`)

### 9.5 Checkpoint Sync Endpoints

```
PulseChain Mainnet:    https://checkpoint.pulsechain.com/eth/v2/debug/beacon/states/finalized
PulseChain Testnet-V4: https://checkpoint.v4.testnet.pulsechain.com/eth/v2/debug/beacon/states/finalized
```

### 9.6 IsPulseChain Detection

```
IsPulseChain() bool:
    return beaconConfig.PresetBase == "pulsechain"
```

### 9.7 Arbitrary-Precision Balance Arithmetic (CRITICAL)

PulseChain's `EffectiveBalanceIncrement` of 1e15 (vs Ethereum's 1e9) means total active balances with millions of validators can overflow 64-bit unsigned integers. **All balance aggregation operations in the CL must use arbitrary-precision integers.**

Affected areas (all must use big integer arithmetic instead of u64):

- **Total balance functions:** `GetTotalActiveBalance`, `GetTotalBalance`, `GetTotalSlashingAmount`
- **Reward computations:** `BaseRewardPerIncrement`, `BaseReward`, `SyncRewards`, `ComputeNextSyncCommittee`
- **Balance caches:** Total active balance cache, total active balance root cache (requires big integer square root)
- **Fork choice weights:** Node weight tracking must use big integers or hex-encoded strings
- **Justification/finalization:** The `3 * totalActive >= 2 * totalBalance` check must use big integer comparison
- **Reward/penalty computations:** All multipliers, denominators, and intermediate values in reward and slashing calculations
- **Epoch data serialization:** `TotalActiveBalance` requires a custom big integer SSZ type
- **API responses:** Balance fields in validator inclusion endpoints should use hex-encoded strings to prevent JSON integer overflow

### 9.8 History Download Fix

The condition for determining EL insertion destination must use `BellatrixForkEpoch != MaxUint64` instead of `DenebForkEpoch != MaxUint64`. This is critical because PulseChain has Bellatrix at epoch 2 but Deneb is not activated (MaxUint64).

### 9.9 Forward Sync Underflow Guard

When computing `startSlot` from `HighestSeen()`, add underflow protection:

```
if highestSeen > 8:
    startSlot = highestSeen - 8
```

---

## 10. Reward Burn

### 10.1 Formula

```
function ApplyBurn(beaconConfig, baseReward):
    afterBurn = baseReward * beaconConfig.SecondsPerSlot / 12
    afterBurn = afterBurn * 3 / 4
    return afterBurn
```

For PulseChain mainnet (10-second slots):
- Step 1: `reward * 10 / 12` = ~83.3% (compensates for faster block times)
- Step 2: `* 3 / 4` = additional 25% burn
- **Effective multiplier: 62.5% of Ethereum-equivalent reward**

### 10.2 Where Burn Is Applied

Burn is applied (`applyBurn = beaconConfig.IsPulseChain()`) to:

- Sync committee participant rewards
- Sync committee proposer rewards
- Attestation proposer rewards
- Epoch rewards/penalties (post-Altair)
- Phase0 proposer/attester rewards

Burn is **NOT applied** to:

- Deposit processing
- Slashing whistleblower rewards
- Validator consolidation balance transfers
- Pending deposits (Electra)

### 10.3 IncreaseBalance Signature Change

```
IncreaseBalance(state, validatorIndex, delta, applyBurn bool) error
```

When `applyBurn` is true, `delta = ApplyBurn(config, delta)` before adding to the validator's balance.

---

## 11. Snapshot and Downloader Support

### 11.1 Snapshot Hashes

PulseChain and PulseChainTestnetV4 have their own snapshot hash manifests, sourced from the PulseChain snapshot repository. Implementations must add entries to their preverified snapshot hash maps.

### 11.2 Remote Preverified Loading

For PulseChain networks, load remote preverified snapshot hashes from `pulseSnapshotHashes.R2` with fallback to `pulseSnapshotHashes.Gitlab`.

### 11.3 Block Types

PulseChain and PulseChainTestnetV4 are registered with `ethereumTypes` snapshot block types (they share Ethereum's block format).

### 11.4 Downloader DB Size

The downloader MDBX MapSize should be increased from 16 GB to 1 TB.

---

## 12. DNS Discovery

### 12.1 KnownDNSNetwork Signature Change

```
KnownDNSNetwork(genesisHash, networkID, protocol) string
```

Add `networkID` parameter.

### 12.2 PulseChain DNS

For PulseChain networks, use:

- **TLD:** `.pulsedisco.net` (instead of `.ethdisco.net`)
- **ENR tree prefix:** `enrtree://APFXO36RU3TWV7XFGWI2TYF5IDA3WM2GPTRL3TCZINWHZX4R6TAOK@`
- **Testnet-V4 subdomain:** `testnet-v4`

### 12.3 Bootnodes

**PulseChain Mainnet:** 10 bootnodes (see reference implementation for exact enode URLs)

**PulseChain Testnet-V4:** 8 bootnodes (see reference implementation for exact enode URLs)

---

## 13. Gas Estimation

### 13.1 20% Padding

After the binary search in `EstimateGas`, add a 20% safety margin:

```
hi = hi + hi / 5
if accountGasLimit != 0 && hi > accountGasLimit:
    hi = accountGasLimit
```

This mitigates gas underestimation issues where EVM execution during estimation differs slightly from actual block execution.

---

## 14. Engine API Adjustments

### 14.1 Withdrawals Presence Check

`checkWithdrawalsPresence` must take both block number and timestamp to use the updated `IsShanghai(num, time)` check.

### 14.2 Block Building

`AssembleBlock` must look up the parent block number from the database to pass to `checkWithdrawalsPresence`.

---

## 15. Detection Mechanisms Summary

PulseChain is detected via multiple complementary methods depending on context:

| Method | When to Use |
|--------|-------------|
| `config.PulseChain != nil` | General PulseChain detection. Used for snapshots, tx pool legacy handling. |
| `config.PrimordialPulseBlock != nil` | Whether this chain has a PrimordialPulse fork configured. |
| `config.PrimordialPulseAhead(num)` | Whether block `num` is in the pre-fork (Ethereum) portion. |
| `config.IsPrimordialPulseBlock(num)` | Whether block `num` is exactly the fork block. |
| `beaconConfig.IsPulseChain()` | CL-side detection. Returns `PresetBase == "pulsechain"`. |
| Chain ID comparison (`369`, `943`) | Genesis config resolution (because genesis hash matches Ethereum). |
| Network name matching | Snapshot config, data directory, DNS discovery. |
