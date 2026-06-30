#!/usr/bin/env python3
"""Upsert a contract release entry in deployment.json (version + channel)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

CHANNELS = frozenset({"dev", "stg", "prod"})


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Upsert a release entry in deployment.json",
    )
    parser.add_argument(
        "deployment",
        type=Path,
        nargs="?",
        help="Path to deployment.json (omit with --print-only)",
    )
    parser.add_argument(
        "--version",
        required=True,
        help="Semver release tag (e.g. v0.1.4)",
    )
    parser.add_argument(
        "--channel",
        required=True,
        choices=sorted(CHANNELS),
        help="Release channel (dev, stg, prod)",
    )
    parser.add_argument(
        "--es256-address",
        default="",
        help="Optional deployed ES256 ImutableUnivocity address",
    )
    parser.add_argument(
        "--ks256-address",
        default="",
        help="Optional deployed KS256 ImutableUnivocity address",
    )
    parser.add_argument(
        "--print-only",
        action="store_true",
        help="Print the release entry JSON array to stdout without writing",
    )
    return parser.parse_args()


def load_deployment(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise SystemExit(f"{path}: root must be a JSON object")
    return data


def normalize_entry(args: argparse.Namespace) -> dict[str, str]:
    version = args.version.strip()
    if not version.startswith("v"):
        version = f"v{version}"
    entry: dict[str, str] = {
        "version": version,
        "channel": args.channel,
    }
    if args.es256_address.strip():
        entry["es256Address"] = args.es256_address.strip()
    if args.ks256_address.strip():
        entry["ks256Address"] = args.ks256_address.strip()
    return entry


def upsert_release(
    deployment: dict[str, Any],
    entry: dict[str, str],
) -> None:
    releases = deployment.get("releases")
    if releases is None:
        releases = []
    if not isinstance(releases, list):
        raise SystemExit("deployment.json releases must be an array")

    key = (entry["version"], entry["channel"])
    updated: list[dict[str, str]] = []
    replaced = False
    for raw in releases:
        if not isinstance(raw, dict):
            raise SystemExit("deployment.json release entry must be an object")
        current_key = (
            str(raw.get("version", "")).strip(),
            str(raw.get("channel", "")).strip(),
        )
        if current_key == key:
            updated.append(entry)
            replaced = True
        else:
            updated.append(raw)
    if not replaced:
        updated.append(entry)
    deployment["releases"] = updated


def main() -> None:
    args = parse_args()
    entry = normalize_entry(args)
    if args.print_only:
        print(json.dumps([entry], indent=2))
        return
    if args.deployment is None:
        raise SystemExit("deployment path is required unless --print-only is set")
    deployment_path = args.deployment
    deployment = load_deployment(deployment_path)
    upsert_release(deployment, entry)
    with deployment_path.open("w", encoding="utf-8") as handle:
        json.dump(deployment, handle, indent=2)
        handle.write("\n")


if __name__ == "__main__":
    main()
