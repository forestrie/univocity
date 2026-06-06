#!/usr/bin/env python3
"""Propose one or more Safe Transaction Builder txs to the Transaction Service."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from eth_utils import to_checksum_address

sys.path.insert(0, str(Path(__file__).resolve().parent))

from safe_eth.eth import EthereumClient

from safe_propose_common import (
    CHAIN_ID,
    ROOT,
    assert_immutable_univocity_deployed,
    assert_safe_deployed,
    fetch_safe_nonce,
    load_batch,
    post_proposed_tx,
    proposer_address,
    require_rpc_and_deploy_key,
    resolve_safe_address,
    safe_tx_from_builder_entry,
    transaction_service_api,
    validate_bootstrap_batch,
)

DEFAULT_BATCH = (
    ROOT
    / "deployments/safe"
    / "imutable-univocity-bootstrap-84532-safe-0x1528b86ff561f617602356efdbD05908a07AA788.json"
)


def main() -> int:
    rpc, pk = require_rpc_and_deploy_key()
    batch_path = Path(os.environ.get("SAFE_BATCH_JSON", DEFAULT_BATCH))
    batch = load_batch(batch_path)
    validate_bootstrap_batch(batch)

    safe = resolve_safe_address(batch_meta=batch.get("meta"))
    safe_version = os.environ.get("SAFE_VERSION", "1.4.1")
    client = EthereumClient(rpc)
    assert_safe_deployed(client, safe)

    univocity = os.environ.get("IMUTABLE_UNIVOCITY_ADDRESS") or to_checksum_address(
        batch["transactions"][1]["to"]
    )
    assert_immutable_univocity_deployed(client, univocity)

    start_nonce = fetch_safe_nonce(client, safe)
    proposer = proposer_address(pk)
    api = transaction_service_api()

    print("Proposing bootstrap Safe transactions")
    print(f"  safe:     {safe}")
    print(f"  proposer: {proposer}")
    print(f"  batch:    {batch_path}")
    print(f"  start_nonce: {start_nonce}")

    for i, entry in enumerate(batch["transactions"]):
        nonce = start_nonce + i
        safe_tx = safe_tx_from_builder_entry(
            client,
            safe,
            entry,
            nonce,
            CHAIN_ID,
            safe_version=safe_version,
        )
        post_proposed_tx(
            api,
            safe_tx,
            pk,
            safe,
            proposer,
            label=f"bootstrap tx[{i}]",
            nonce=nonce,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
