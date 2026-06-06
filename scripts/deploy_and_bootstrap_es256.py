#!/usr/bin/env python3
"""Deploy ImutableUnivocity (ES256) and bootstrap root authority log."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from es256_common import mnemonic_uuid_from_address  # noqa: E402


def main() -> int:
    env = os.environ.copy()
    deploy = subprocess.run(
        [sys.executable, str(ROOT / "scripts/deploy_imutable_es256.py")],
        env=env,
        capture_output=True,
        text=True,
    )
    print(deploy.stdout, end="")
    print(deploy.stderr, end="", file=sys.stderr)
    if deploy.returncode != 0:
        return deploy.returncode

    address = ""
    for line in deploy.stdout.splitlines():
        if line.startswith("IMUTABLE_UNIVOCITY_ADDRESS="):
            address = line.split("=", 1)[1].strip()
            break
    if not address:
        print("Could not parse IMUTABLE_UNIVOCITY_ADDRESS from deploy", file=sys.stderr)
        return 4
    env["IMUTABLE_UNIVOCITY_ADDRESS"] = address

    bootstrap = subprocess.run(
        [sys.executable, str(ROOT / "scripts/bootstrap_es256_root.py")],
        env=env,
    )
    if bootstrap.returncode != 0:
        return bootstrap.returncode

    log_id = mnemonic_uuid_from_address(address)
    print(f"E2E_UNIVOCITY_ADDRESS_ES256_BOOTSTRAP={address}")
    print(f"E2E_UNIVOCITY_GENESIS_LOG_ID_ES256={log_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
