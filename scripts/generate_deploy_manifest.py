#!/usr/bin/env python3
"""Generate deploy-manifest-<release-id>.json from forge out/ artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


def bytecode_sha256(hex_bytecode: str) -> str:
    raw = bytes.fromhex(hex_bytecode.removeprefix("0x"))
    return hashlib.sha256(raw).hexdigest()


def load_artifact(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must be a JSON object")
    return data


def contract_entry(path: Path) -> dict[str, Any]:
    artifact = load_artifact(path)
    bytecode_obj = artifact.get("bytecode")
    if not isinstance(bytecode_obj, dict):
        raise ValueError(f"{path} missing bytecode object")
    creation = bytecode_obj.get("object")
    if not isinstance(creation, str) or not creation.startswith("0x"):
        raise ValueError(f"{path} missing bytecode.object hex")

    contract_name = path.stem
    metadata_raw = artifact.get("metadata")
    solc_version = "unknown"
    if isinstance(metadata_raw, str):
        try:
            metadata = json.loads(metadata_raw)
            compiler = metadata.get("compiler")
            if isinstance(compiler, dict):
                version = compiler.get("version")
                if isinstance(version, str):
                    solc_version = version
        except json.JSONDecodeError:
            pass

    abi = artifact.get("abi")
    constructor_abi: list[Any] = []
    if isinstance(abi, list):
        constructor_abi = [
            item for item in abi if isinstance(item, dict) and item.get("type") == "constructor"
        ]

    entry: dict[str, Any] = {
        "contractName": contract_name,
        "creationBytecode": creation,
        "bytecodeSha256": bytecode_sha256(creation),
        "solcVersion": solc_version,
    }
    if constructor_abi:
        entry["constructorAbi"] = constructor_abi
    return entry


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("release_id", help="Release tag, e.g. v0.4.0")
    parser.add_argument(
        "--out-dir",
        default="out",
        help="Foundry out directory for ImutableUnivocity (default: out)",
    )
    parser.add_argument(
        "--create3-out-dir",
        default="script/create3-factory/out",
        help="Foundry out directory for CREATE3Factory "
        "(default: script/create3-factory/out)",
    )
    parser.add_argument(
        "--output",
        help="Output path (default: deploy-manifest-<release_id>.json)",
    )
    args = parser.parse_args(argv)

    out_dir = Path(args.out_dir)
    imutable_path = out_dir / "ImutableUnivocity.sol" / "ImutableUnivocity.json"
    if not imutable_path.is_file():
        raise SystemExit(f"missing artifact: {imutable_path}")

    contracts: dict[str, Any] = {
        "ImutableUnivocity": contract_entry(imutable_path),
    }

    factory_path = Path(args.create3_out_dir) / "CREATE3Factory.sol" / "CREATE3Factory.json"
    if factory_path.is_file():
        contracts["CREATE3Factory"] = contract_entry(factory_path)

    manifest = {
        "version": 1,
        "releaseId": args.release_id,
        "contracts": contracts,
    }

    output = Path(args.output or f"deploy-manifest-{args.release_id}.json")
    output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
