#!/usr/bin/env python3
"""Verify deploy-manifest bytecode matches a forge artifact JSON."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from generate_deploy_manifest import bytecode_sha256, contract_entry


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, help="deploy-manifest JSON path")
    parser.add_argument(
        "artifact",
        type=Path,
        help="ImutableUnivocity forge artifact JSON path",
    )
    args = parser.parse_args(argv)

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    entry = manifest.get("contracts", {}).get("ImutableUnivocity")
    if not isinstance(entry, dict):
        raise SystemExit("manifest missing contracts.ImutableUnivocity")

    artifact_entry = contract_entry(args.artifact)
    for field in ("creationBytecode", "bytecodeSha256"):
        manifest_value = entry.get(field)
        artifact_value = artifact_entry.get(field)
        if manifest_value != artifact_value:
            raise SystemExit(
                f"manifest {field} mismatch: manifest={manifest_value!r} "
                f"artifact={artifact_value!r}",
            )

    print(f"OK: {args.manifest} matches {args.artifact}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
