#!/usr/bin/env python3
"""Propose the deploy-only Safe Transaction Builder batch to the Safe Transaction Service."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from eth_account import Account
from eth_utils import to_checksum_address
from safe_eth.eth import EthereumClient, EthereumNetwork
from safe_eth.eth.constants import NULL_ADDRESS
from safe_eth.safe import SafeTx
from safe_eth.safe.api import TransactionServiceApi
from safe_eth.safe.api.base_api import SafeAPIException

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SAFE = "0x1528b86ff561f617602356efdbD05908a07AA788"
DEFAULT_BATCH = (
    ROOT
    / "deployments/safe"
    / "imutable-univocity-84532-safe-0x1528b86ff561f617602356efdbD05908a07AA788.json"
)
CHAIN_ID = 84532


def main() -> int:
    rpc = os.environ.get("RPC_URL")
    pk = os.environ.get("DEPLOY_KEY")
    if not rpc or not pk:
        print("RPC_URL and DEPLOY_KEY are required", file=sys.stderr)
        return 1
    if not pk.startswith("0x"):
        pk = "0x" + pk

    safe = to_checksum_address(os.environ.get("SAFE_ADDRESS", DEFAULT_SAFE))
    batch_path = Path(os.environ.get("SAFE_BATCH_JSON", DEFAULT_BATCH))
    safe_version = os.environ.get("SAFE_VERSION", "1.4.1")
    safe_nonce = int(os.environ.get("SAFE_NONCE", "0"))

    client = EthereumClient(rpc)
    code = client.w3.eth.get_code(safe)
    if code in (b"", b"0x"):
        print(
            f"Safe {safe} has no contract code on chain {CHAIN_ID}. "
            "Deploy or activate the Safe on Base Sepolia before proposing.",
            file=sys.stderr,
        )
        return 2

    batch = json.loads(batch_path.read_text())
    tx0 = batch["transactions"][0]
    proposer = Account.from_key(pk).address

    safe_tx = SafeTx(
        client,
        safe,
        to_checksum_address(tx0["to"]),
        int(tx0["value"]),
        bytes.fromhex(tx0["data"][2:]),
        int(tx0["operation"]),
        0,
        0,
        0,
        NULL_ADDRESS,
        NULL_ADDRESS,
        safe_nonce=safe_nonce,
        safe_version=safe_version,
        chain_id=CHAIN_ID,
    )
    safe_tx.sign(pk)

    api = TransactionServiceApi(network=EthereumNetwork.BASE_SEPOLIA_TESTNET)
    try:
        api.post_transaction(safe_tx)
    except SafeAPIException as exc:
        print(exc, file=sys.stderr)
        return 3

    tx_hash = safe_tx.safe_tx_hash.hex()
    print("Proposed multisig transaction")
    print(f"  safe:     {safe}")
    print(f"  proposer: {proposer}")
    print(f"  safeTxHash: {tx_hash}")
    print(
        "  dashboard: "
        f"https://app.safe.global/transactions/tx?safe=basesep:{safe}&id=multisig_{tx_hash}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
