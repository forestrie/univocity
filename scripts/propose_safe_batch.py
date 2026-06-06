#!/usr/bin/env python3
"""Propose one or more Safe Transaction Builder txs to the Transaction Service."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from eth_account import Account
from eth_utils import to_checksum_address
from safe_eth.eth import EthereumClient, EthereumNetwork
from safe_eth.eth.constants import NULL_ADDRESS
from safe_eth.safe import Safe, SafeTx
from safe_eth.safe.api import TransactionServiceApi
from safe_eth.safe.api.base_api import SafeAPIException
from safe_eth.safe.enums import SafeOperationEnum

ROOT = Path(__file__).resolve().parents[1]
CHAIN_ID = 84532


def _load_batch(path: Path) -> dict:
    return json.loads(path.read_text())


def _safe_tx_from_builder_entry(
    client: EthereumClient,
    safe: str,
    entry: dict,
    nonce: int,
    chain_id: int,
) -> SafeTx:
    operation = (
        SafeOperationEnum.DELEGATE_CALL.value
        if int(entry["operation"]) == 1
        else SafeOperationEnum.CALL.value
    )
    data_hex = entry["data"]
    data = bytes.fromhex(data_hex[2:] if data_hex.startswith("0x") else data_hex)
    return SafeTx(
        client,
        to_checksum_address(safe),
        to_checksum_address(entry["to"]),
        int(entry.get("value", 0)),
        data,
        operation,
        int(entry.get("safeTxGas", 0)),
        int(entry.get("baseGas", 0)),
        int(entry.get("gasPrice", 0)),
        to_checksum_address(entry.get("gasToken", NULL_ADDRESS)),
        to_checksum_address(entry.get("refundReceiver", NULL_ADDRESS)),
        safe_nonce=nonce,
        safe_version="1.4.1",
        chain_id=chain_id,
    )


def main() -> int:
    rpc = os.environ.get("RPC_URL")
    pk = os.environ.get("DEPLOY_KEY")
    batch_path = Path(
        os.environ.get(
            "SAFE_BATCH_JSON",
            ROOT
            / "deployments/safe/imutable-univocity-bootstrap-84532-safe-0x1528b86ff561f617602356efdbD05908a07AA788.json",
        )
    )
    if not rpc or not pk:
        print("RPC_URL and DEPLOY_KEY are required", file=sys.stderr)
        return 1
    if not pk.startswith("0x"):
        pk = "0x" + pk

    batch = _load_batch(batch_path)
    safe = to_checksum_address(
        os.environ.get("SAFE_ADDRESS", batch["meta"]["createdFromSafeAddress"])
    )
    client = EthereumClient(rpc)
    code = client.w3.eth.get_code(safe)
    if code in (b"", b"0x"):
        print(f"Safe {safe} is not deployed", file=sys.stderr)
        return 2

    safe_contract = Safe(safe, client)
    start_nonce = safe_contract.retrieve_nonce()
    proposer = Account.from_key(pk).address
    api = TransactionServiceApi(network=EthereumNetwork.BASE_SEPOLIA_TESTNET)

    proposed = []
    for i, entry in enumerate(batch["transactions"]):
        nonce = start_nonce + i
        safe_tx = _safe_tx_from_builder_entry(client, safe, entry, nonce, CHAIN_ID)
        safe_tx.sign(pk)
        try:
            api.post_transaction(safe_tx)
        except SafeAPIException as exc:
            print(f"Failed tx index {i} nonce {nonce}: {exc}", file=sys.stderr)
            return 3
        proposed.append(
            {
                "index": i,
                "nonce": nonce,
                "to": entry["to"],
                "operation": entry["operation"],
                "safeTxHash": safe_tx.safe_tx_hash.hex(),
            }
        )

    print("Proposed Safe transactions")
    print(f"  safe:     {safe}")
    print(f"  proposer: {proposer}")
    print(f"  batch:    {batch_path}")
    for row in proposed:
        h = row["safeTxHash"]
        print(
            f"  [{row['index']}] nonce={row['nonce']} to={row['to']} "
            f"op={row['operation']}"
        )
        print(
            "      dashboard: "
            f"https://app.safe.global/transactions/tx?safe=basesep:{safe}&id=multisig_{h}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
