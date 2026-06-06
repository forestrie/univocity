#!/usr/bin/env python3
"""Deploy ImutableUnivocity with ES256 bootstrap (non-interactive)."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from es256_common import (  # noqa: E402
    load_pem_es256_coords,
    parse_deployed_address,
    require_env,
    select_gas_payer_private_key,
)


def main() -> int:
    rpc_url = require_env("RPC_URL")
    coords = load_pem_es256_coords()
    gas_pk, gas_addr = select_gas_payer_private_key(rpc_url)

    env = os.environ.copy()
    env["ES256_X"] = coords.x_hex
    env["ES256_Y"] = coords.y_hex
    env["PRIVATE_KEY"] = gas_pk

    print(f"Broadcasting DeployUnivocity from {gas_addr}")
    proc = subprocess.run(
        [
            "forge",
            "script",
            "script/Deploy.s.sol:DeployUnivocity",
            "--rpc-url",
            rpc_url,
            "--private-key",
            gas_pk,
            "--broadcast",
        ],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
    )
    combined = proc.stdout + proc.stderr
    print(combined, end="")
    if proc.returncode != 0:
        return proc.returncode

    address = parse_deployed_address(combined)
    if not address:
        print("Could not parse deployed address from forge output", file=sys.stderr)
        return 3

    print(f"IMUTABLE_UNIVOCITY_ADDRESS={address}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
