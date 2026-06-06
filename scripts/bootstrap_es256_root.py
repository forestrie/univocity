#!/usr/bin/env python3
"""Bootstrap ES256 ImutableUnivocity root authority log."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from es256_common import (  # noqa: E402
    load_pem_es256_coords,
    require_env,
    select_gas_payer_private_key,
)


def es256_private_key_scalar() -> str:
    pem_text = require_env("BOOTSTRAP_PEM_ES256")
    key = serialization.load_pem_private_key(pem_text.encode(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise SystemExit("BOOTSTRAP_PEM_ES256 must be an EC private key")
    return str(key.private_numbers().private_value)


def main() -> int:
    rpc_url = require_env("RPC_URL")
    univocity = require_env("IMUTABLE_UNIVOCITY_ADDRESS")
    coords = load_pem_es256_coords()
    gas_pk, gas_addr = select_gas_payer_private_key(rpc_url)
    es256_pk = es256_private_key_scalar()

    env = os.environ.copy()
    env["IMUTABLE_UNIVOCITY_ADDRESS"] = univocity
    env["ES256_X"] = coords.x_hex
    env["ES256_Y"] = coords.y_hex
    env["ES256_PRIVATE_KEY"] = es256_pk
    env["PRIVATE_KEY"] = gas_pk

    print(f"Bootstrapping {univocity} (gas payer {gas_addr})")
    proc = subprocess.run(
        [
            "forge",
            "script",
            "script/BootstrapEs256Root.s.sol:BootstrapEs256Root",
            "--rpc-url",
            rpc_url,
            "--private-key",
            gas_pk,
            "--broadcast",
        ],
        cwd=ROOT,
        env=env,
        text=True,
    )
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
