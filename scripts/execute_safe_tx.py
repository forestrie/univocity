#!/usr/bin/env python3
"""Sign and execute a Safe multisig transaction locally (bypasses Safe UI)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from eth_account import Account
from eth_utils import to_checksum_address
from safe_eth.eth import EthereumClient, TxSpeed
from safe_eth.safe import Safe
from safe_eth.safe.api import TransactionServiceApi
from safe_eth.safe.api.base_api import SafeAPIException

from safe_propose_common import (
    CHAIN_ID,
    ROOT,
    assert_safe_deployed,
    dashboard_url,
    fetch_safe_nonce,
    load_batch,
    predict_immutable_univocity_from_create2_calldata,
    resolve_safe_address,
    safe_tx_from_builder_entry,
    transaction_service_api,
)

DEFAULT_DEPLOY_BATCH = (
    ROOT
    / "deployments/safe"
    / "imutable-univocity-84532-safe-0x1528b86ff561f617602356efdbD05908a07AA788.json"
)
DEFAULT_DEPLOY_SAFE_TX_HASH = (
    "0xe7b4e2223bd8fdc1e20bcc151e111350b11ad8ef30e52ef6581f9987b572b1d4"
)


def require_rpc_and_private_key() -> tuple[str, str]:
    rpc = os.environ.get("RPC_URL")
    pk = os.environ.get("PRIVATE_KEY") or os.environ.get("SAFE_OWNER_PRIVATE_KEY")
    if not rpc or not pk:
        print(
            "RPC_URL and PRIVATE_KEY (or SAFE_OWNER_PRIVATE_KEY) are required",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if not pk.startswith("0x"):
        pk = "0x" + pk
    return rpc, pk


def assert_signer_is_owner(client: EthereumClient, safe: str, signer: str) -> None:
    owners = [to_checksum_address(o) for o in Safe(safe, client).retrieve_owners()]
    signer = to_checksum_address(signer)
    if signer not in owners:
        print(
            f"Signer {signer} is not a Safe owner. On-chain owners: {owners}",
            file=sys.stderr,
        )
        print(
            "Add the signer as an owner (swapOwner) before executing, or use an "
            "existing owner key.",
            file=sys.stderr,
        )
        raise SystemExit(2)


def load_safe_tx_from_service(
    client: EthereumClient, safe_tx_hash: str
):
    api = transaction_service_api(ethereum_client=client)
    safe_tx, executed_tx_hash = api.get_safe_transaction(safe_tx_hash)
    if executed_tx_hash:
        print(
            f"Transaction already executed on-chain: {executed_tx_hash.hex()}",
            file=sys.stderr,
        )
        raise SystemExit(3)
    return safe_tx


def load_safe_tx_from_batch(
    client: EthereumClient,
    batch_path: Path,
    safe: str,
    safe_nonce: int,
    safe_version: str,
):
    batch = load_batch(batch_path)
    txs = batch.get("transactions", [])
    if len(txs) != 1:
        print(
            "Batch execution currently supports exactly one transaction per run. "
            f"Got {len(txs)} in {batch_path}.",
            file=sys.stderr,
        )
        raise SystemExit(4)

    return safe_tx_from_builder_entry(
        client,
        safe,
        txs[0],
        safe_nonce,
        CHAIN_ID,
        safe_version=safe_version,
    )


def normalize_tx_hash(value: str) -> str:
    stripped = value.lower().removeprefix("0x")
    return f"0x{stripped}"


def resolve_safe_tx(
    client: EthereumClient,
    safe: str,
    safe_version: str,
):
    safe_tx_hash = normalize_tx_hash(
        os.environ.get("SAFE_TX_HASH", DEFAULT_DEPLOY_SAFE_TX_HASH)
    )
    batch_path = Path(os.environ.get("SAFE_BATCH_JSON", DEFAULT_DEPLOY_BATCH))

    if os.environ.get("SAFE_TX_SOURCE", "service").lower() == "batch":
        if "SAFE_NONCE" in os.environ:
            safe_nonce = int(os.environ["SAFE_NONCE"])
        else:
            safe_nonce = fetch_safe_nonce(client, safe)
        safe_tx = load_safe_tx_from_batch(
            client, batch_path, safe, safe_nonce, safe_version
        )
        rebuilt = normalize_tx_hash(safe_tx.safe_tx_hash.hex())
        if rebuilt != safe_tx_hash:
            print(
                f"Batch rebuild hash {rebuilt} does not match SAFE_TX_HASH {safe_tx_hash}",
                file=sys.stderr,
            )
            raise SystemExit(4)
        return safe_tx

    return load_safe_tx_from_service(client, safe_tx_hash)


def maybe_verify_deploy(client: EthereumClient, safe_tx) -> None:
    predicted = predict_immutable_univocity_from_create2_calldata(safe_tx.data)
    if not predicted:
        return

    code = client.w3.eth.get_code(predicted)
    if code not in (b"", b"0x"):
        print(f"ImutableUnivocity already deployed at {predicted}")
    else:
        print(f"Expected ImutableUnivocity address after execution: {predicted}")


def main() -> int:
    rpc, pk = require_rpc_and_private_key()
    signer = Account.from_key(pk).address
    safe = resolve_safe_address()
    safe_version = os.environ.get("SAFE_VERSION", "1.4.1")
    dry_run = os.environ.get("DRY_RUN", "").lower() in ("1", "true", "yes")
    confirm_only = os.environ.get("CONFIRM_ONLY", "").lower() in ("1", "true", "yes")

    client = EthereumClient(rpc)
    assert_safe_deployed(client, safe)
    assert_signer_is_owner(client, safe, signer)

    safe_tx = resolve_safe_tx(client, safe, safe_version)
    safe_tx_hash = safe_tx.safe_tx_hash.hex()
    print(f"Safe:       {safe}")
    print(f"Signer:     {signer}")
    print(f"safeTxHash: 0x{safe_tx_hash}")
    print(f"nonce:      {safe_tx.safe_nonce}")
    print(f"to:         {safe_tx.to}")
    print(f"dashboard:  {dashboard_url(safe, safe_tx_hash)}")

    maybe_verify_deploy(client, safe_tx)

    print("Signing Safe transaction for simulation...")
    signature = safe_tx.sign(pk)
    print(f"Signed ({len(signature)} bytes)")

    print("Simulating Safe transaction...")
    safe_tx.call(tx_sender_address=signer)
    print("Simulation OK")

    if dry_run:
        print("DRY_RUN set; skipping on-chain execute")
        return 0

    if confirm_only:
        api = transaction_service_api(ethereum_client=client)
        try:
            api.post_signatures(safe_tx.safe_tx_hash, signature)
        except SafeAPIException as exc:
            print(f"Failed to post confirmation: {exc}", file=sys.stderr)
            raise SystemExit(5) from exc
        print("Posted confirmation to Transaction Service (not executed on-chain)")
        return 0

    print("Executing on-chain...")
    tx_hash, _tx = safe_tx.execute(pk, eip1559_speed=TxSpeed.FAST)
    print(f"Execution tx hash: {tx_hash.hex()}")

    receipt = client.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
    if receipt["status"] != 1:
        print(f"Execution reverted (status={receipt['status']})", file=sys.stderr)
        raise SystemExit(6)

    predicted = predict_immutable_univocity_from_create2_calldata(safe_tx.data)
    if predicted:
        code = client.w3.eth.get_code(predicted)
        if code in (b"", b"0x"):
            print(
                f"Warning: no code yet at predicted address {predicted}",
                file=sys.stderr,
            )
        else:
            print(f"ImutableUnivocity deployed at {predicted}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
