#!/usr/bin/env python3
"""Captures one fixture for the `pulsechain` eth_feeHistory reward differential test.

It asks rpc.pulsechain.com (erigon) for eth_feeHistory over BLOCKS blocks that end at a pinned
block number N, once per percentile set, and stores the rewards with those blocks, reduced to what
the reward calculation reads: per block the number, coinbase, base fee and gas used, and per
transaction its type, fee fields, sender, recipient and gas used (from eth_getBlockReceipts).

N is a few blocks below the head, so every request reads the same blocks. The script checks that
the receipts' cumulative gas agrees with each receipt's gas used, and that the fetched blocks link.

Usage: python3 -I capture.py <out-dir> [count]
"""

import json
import sys
import time
import urllib.request

RPC = "https://rpc.pulsechain.com"
BLOCKS = 8
BELOW_HEAD = 5
PERCENTILE_SETS = [[10, 50, 90], [25, 75], [0, 5, 99.5, 100], [12.5, 33.3, 66.7]]


def call(batch):
    body = json.dumps(
        [{"jsonrpc": "2.0", "id": i, "method": m, "params": p} for i, (m, p) in enumerate(batch)]
    ).encode()
    req = urllib.request.Request(
        RPC, data=body, headers={"content-type": "application/json", "user-agent": "gpo-fixture"}
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        out = sorted(json.load(r), key=lambda x: x["id"])
    for x in out:
        if "error" in x:
            raise RuntimeError(x["error"])
    return [x["result"] for x in out]


def tx_row(tx, receipt):
    kind = int(tx["type"], 16)
    if kind == 0 or kind == 1:
        fees = [tx["gasPrice"], None]
    else:
        fees = [tx["maxFeePerGas"], tx["maxPriorityFeePerGas"]]
    to = tx["to"].lower() if tx.get("to") else None
    return [kind, *fees, tx["from"].lower(), to, int(receipt["gasUsed"], 16)]


def capture():
    (head,) = call([("eth_blockNumber", [])])
    newest = int(head, 16) - BELOW_HEAD
    numbers = list(range(newest - BLOCKS + 1, newest + 1))
    histories = call(
        [("eth_feeHistory", [hex(BLOCKS), hex(newest), ps]) for ps in PERCENTILE_SETS]
    )
    blocks = call([("eth_getBlockByNumber", [hex(n), True]) for n in numbers])
    receipts = call([("eth_getBlockReceipts", [hex(n)]) for n in numbers])
    for parent, child in zip(blocks, blocks[1:]):
        if child["parentHash"] != parent["hash"]:
            raise RuntimeError("the fetched blocks do not link")
    for h in histories:
        if int(h["oldestBlock"], 16) != numbers[0] or len(h["reward"]) != BLOCKS:
            raise RuntimeError("the fee history does not cover the fetched blocks")
    rows = []
    for b, rs in zip(blocks, receipts):
        if len(rs) != len(b["transactions"]):
            raise RuntimeError("receipt count")
        prev = 0
        for r in rs:
            cumulative = int(r["cumulativeGasUsed"], 16)
            if cumulative - prev != int(r["gasUsed"], 16):
                raise RuntimeError("gas used disagrees with cumulative gas")
            prev = cumulative
        rows.append(
            {
                "number": int(b["number"], 16),
                "hash": b["hash"],
                "coinbase": b["miner"].lower(),
                "baseFee": b.get("baseFeePerGas"),
                "gasUsed": int(b["gasUsed"], 16),
                "txs": [tx_row(t, r) for t, r in zip(b["transactions"], rs)],
            }
        )
    return {
        "chainId": 369,
        "newest": newest,
        "histories": [
            {"percentiles": ps, "reward": h["reward"]} for ps, h in zip(PERCENTILE_SETS, histories)
        ],
        "blocks": rows,
    }


def main():
    out_dir = sys.argv[1]
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    for i in range(count):
        if i:
            time.sleep(90)
        fx = capture()
        path = f"{out_dir}/newest-{fx['newest']}.json"
        with open(path, "w") as f:
            json.dump(fx, f, separators=(",", ":"))
            f.write("\n")
        print(path, sum(len(b["txs"]) for b in fx["blocks"]), "txs")


if __name__ == "__main__":
    main()
