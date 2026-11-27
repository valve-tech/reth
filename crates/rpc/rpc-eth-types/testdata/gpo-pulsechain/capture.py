#!/usr/bin/env python3
"""Captures one fixture for the `pulsechain` gas price oracle differential test.

At a head H, rpc.pulsechain.com (erigon) answers `eth_maxPriorityFeePerGas`. This script stores
that answer with the 20 blocks H-19..H that erigon's oracle samples, reduced to what the
algorithm reads: per block the number, hash, coinbase and base fee, and per transaction its
type, fee fields, sender and recipient.

The head must not move while the answer is read: one batch reads the block number, the answer
and the block number again, and the script retries until both numbers agree. The fetched block
H must then carry the hash that the batch saw.

Usage: python3 -I capture.py <out-dir> [count]
"""

import json
import sys
import time
import urllib.request

RPC = "https://rpc.pulsechain.com"
BLOCKS = 20


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


def tx_row(tx):
    kind = int(tx["type"], 16)
    if kind == 0 or kind == 1:
        fees = [tx["gasPrice"], None]
    else:
        fees = [tx["maxFeePerGas"], tx["maxPriorityFeePerGas"]]
    return [kind, *fees, tx["from"].lower(), tx["to"].lower() if tx.get("to") else None]


def capture():
    while True:
        n1, answer, gas_price, latest, n2 = call(
            [
                ("eth_blockNumber", []),
                ("eth_maxPriorityFeePerGas", []),
                ("eth_gasPrice", []),
                ("eth_getBlockByNumber", ["latest", False]),
                ("eth_blockNumber", []),
            ]
        )
        if n1 == n2 == latest["number"]:
            break
        time.sleep(1)
    head = int(n1, 16)
    blocks = call(
        [("eth_getBlockByNumber", [hex(n), True]) for n in range(head, head - BLOCKS, -1)]
    )
    if blocks[0]["hash"] != latest["hash"]:
        raise RuntimeError("block H changed between the answer and the block fetch")
    for child, parent in zip(blocks, blocks[1:]):
        if child["parentHash"] != parent["hash"]:
            raise RuntimeError("the fetched blocks do not link")
    return {
        "chainId": 369,
        "head": head,
        "headHash": latest["hash"],
        "maxPriorityFeePerGas": answer,
        "gasPrice": gas_price,
        "blocks": [
            {
                "number": int(b["number"], 16),
                "hash": b["hash"],
                "coinbase": b["miner"].lower(),
                "baseFee": b.get("baseFeePerGas"),
                "txs": [tx_row(t) for t in b["transactions"]],
            }
            for b in blocks
        ],
    }


def main():
    out_dir = sys.argv[1]
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    for i in range(count):
        if i:
            time.sleep(25)
        fx = capture()
        path = f"{out_dir}/head-{fx['head']}.json"
        with open(path, "w") as f:
            json.dump(fx, f, separators=(",", ":"))
            f.write("\n")
        print(path, fx["maxPriorityFeePerGas"], sum(len(b["txs"]) for b in fx["blocks"]), "txs")


if __name__ == "__main__":
    main()
