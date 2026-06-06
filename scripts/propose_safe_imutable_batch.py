#!/usr/bin/env python3
"""Propose the deploy-only Safe Transaction Builder batch to the Safe Transaction Service."""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from safe_eth.eth import EthereumClient

from safe_propose_common import (
    CHAIN_ID,
    ROOT,
    assert_safe_deployed,
    fetch_safe_nonce,
    load_batch,
    post_proposed_tx,
    proposer_address,
    require_rpc_and_deploy_key,
    resolve_safe_address,
    safe_tx_from_builder_entry,
    transaction_service_api,
    validate_deploy_batch,
)

DEFAULT_BATCH = (
    ROOT
    / "deployments/safe"
    / "imutable-univocity-84532-safe-0x1528b86ff561f617602356efdbD05908a07AA788.json"
)


def main() -> int:
    rpc, pk = require_rpc_and_deploy_key()
    batch_path = Path(os.environ.get("SAFE_BATCH_JSON", DEFAULT_BATCH))
    batch = load_batch(batch_path)
    validate_deploy_batch(batch)

    safe = resolve_safe_address(batch_meta=batch.get("meta"))
    safe_version = os.environ.get("SAFE_VERSION", "1.4.1")
    client = EthereumClient(rpc)
    assert_safe_deployed(client, safe)
    if "SAFE_NONCE" in os.environ:
        safe_nonce = int(os.environ["SAFE_NONCE"])
    else:
        safe_nonce = fetch_safe_nonce(client, safe)

    proposer = proposer_address(pk)
    tx0 = batch["transactions"][0]
    safe_tx = safe_tx_from_builder_entry(
        client,
        safe,
        tx0,
        safe_nonce,
        CHAIN_ID,
        safe_version=safe_version,
    )

    api = transaction_service_api()
    post_proposed_tx(
        api,
        safe_tx,
        pk,
        safe,
        proposer,
        label="deploy ImutableUnivocity",
        batch_path=batch_path,
        nonce=safe_nonce,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
