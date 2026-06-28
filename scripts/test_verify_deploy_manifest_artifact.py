"""Tests for scripts/verify_deploy_manifest_artifact.py."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from generate_deploy_manifest import main as generate_main
from verify_deploy_manifest_artifact import main as verify_main


class VerifyDeployManifestArtifactTest(unittest.TestCase):
    def test_accepts_matching_manifest_and_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out_dir = root / "out"
            artifact_dir = out_dir / "ImutableUnivocity.sol"
            artifact_dir.mkdir(parents=True)
            bytecode = "0x6001"
            (artifact_dir / "ImutableUnivocity.json").write_text(
                json.dumps(
                    {
                        "bytecode": {"object": bytecode},
                        "metadata": json.dumps(
                            {"compiler": {"version": "0.8.26+commit.abc"}}
                        ),
                        "abi": [{"type": "constructor", "inputs": []}],
                    }
                ),
                encoding="utf-8",
            )
            manifest_path = root / "deploy-manifest-v0.4.0.json"
            self.assertEqual(
                generate_main(
                    [
                        "v0.4.0",
                        "--out-dir",
                        str(out_dir),
                        "--output",
                        str(manifest_path),
                    ]
                ),
                0,
            )
            self.assertEqual(
                verify_main(
                    [
                        str(manifest_path),
                        str(artifact_dir / "ImutableUnivocity.json"),
                    ]
                ),
                0,
            )

    def test_rejects_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_path = root / "deploy-manifest-v0.4.0.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "releaseId": "v0.4.0",
                        "contracts": {
                            "ImutableUnivocity": {
                                "contractName": "ImutableUnivocity",
                                "creationBytecode": "0x6001",
                                "bytecodeSha256": "deadbeef",
                                "solcVersion": "0.8.26",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            artifact_path = root / "ImutableUnivocity.json"
            artifact_path.write_text(
                json.dumps({"bytecode": {"object": "0x6002"}}),
                encoding="utf-8",
            )
            with self.assertRaises(SystemExit):
                verify_main([str(manifest_path), str(artifact_path)])

    def test_accepts_uups_univocity_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out_dir = root / "out"
            imutable_dir = out_dir / "ImutableUnivocity.sol"
            imutable_dir.mkdir(parents=True)
            (imutable_dir / "ImutableUnivocity.json").write_text(
                json.dumps(
                    {
                        "bytecode": {"object": "0x6001"},
                        "metadata": json.dumps(
                            {"compiler": {"version": "0.8.26+commit.abc"}}
                        ),
                        "abi": [{"type": "constructor", "inputs": []}],
                    }
                ),
                encoding="utf-8",
            )
            artifact_dir = out_dir / "UUPSUnivocity.sol"
            artifact_dir.mkdir(parents=True)
            bytecode = "0x6002"
            (artifact_dir / "UUPSUnivocity.json").write_text(
                json.dumps(
                    {
                        "bytecode": {"object": bytecode},
                        "metadata": json.dumps(
                            {"compiler": {"version": "0.8.26+commit.abc"}}
                        ),
                        "abi": [
                            {
                                "type": "function",
                                "name": "initialize",
                                "inputs": [],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            manifest_path = root / "deploy-manifest-v0.4.0.json"
            self.assertEqual(
                generate_main(
                    [
                        "v0.4.0",
                        "--out-dir",
                        str(out_dir),
                        "--output",
                        str(manifest_path),
                    ]
                ),
                0,
            )
            self.assertEqual(
                verify_main(
                    [
                        str(manifest_path),
                        str(artifact_dir / "UUPSUnivocity.json"),
                        "--contract",
                        "UUPSUnivocity",
                    ]
                ),
                0,
            )


if __name__ == "__main__":
    unittest.main()
