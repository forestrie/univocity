"""Tests for scripts/generate_deploy_manifest.py."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from generate_deploy_manifest import bytecode_sha256, contract_entry, main


class GenerateDeployManifestTest(unittest.TestCase):
    def test_bytecode_sha256_known_vector(self) -> None:
        digest = bytecode_sha256("0x6001")
        self.assertEqual(len(digest), 64)
        self.assertEqual(
            digest,
            "9e67b12fd8c58953460459cad7a6d4dd7d6d57594affce8206d1397c9c4db543",
        )

    def test_contract_entry_from_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ImutableUnivocity.json"
            bytecode = "0x6001"
            path.write_text(
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
            entry = contract_entry(path)
            self.assertEqual(entry["contractName"], "ImutableUnivocity")
            self.assertEqual(entry["creationBytecode"], bytecode)
            self.assertEqual(entry["bytecodeSha256"], bytecode_sha256(bytecode))
            self.assertEqual(entry["solcVersion"], "0.8.26+commit.abc")

    def test_main_matches_golden_fixture_shape(self) -> None:
        golden_path = (
            Path(__file__).resolve().parent.parent
            / "test"
            / "fixtures"
            / "deploy-manifest.fixture.json"
        )
        golden = json.loads(golden_path.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            artifact_dir = out_dir / "ImutableUnivocity.sol"
            artifact_dir.mkdir(parents=True)
            bytecode = golden["contracts"]["ImutableUnivocity"]["creationBytecode"]
            (artifact_dir / "ImutableUnivocity.json").write_text(
                json.dumps(
                    {
                        "bytecode": {"object": bytecode},
                        "metadata": json.dumps(
                            {
                                "compiler": {
                                    "version": golden["contracts"][
                                        "ImutableUnivocity"
                                    ]["solcVersion"],
                                }
                            }
                        ),
                        "abi": golden["contracts"]["ImutableUnivocity"].get(
                            "constructorAbi", []
                        ),
                    }
                ),
                encoding="utf-8",
            )
            output = Path(tmp) / "deploy-manifest-v0.4.0-fixture.json"
            rc = main(
                [
                    "v0.4.0-fixture",
                    "--out-dir",
                    str(out_dir),
                    "--output",
                    str(output),
                ]
            )
            self.assertEqual(rc, 0)
            generated = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(generated["version"], golden["version"])
            self.assertEqual(generated["releaseId"], golden["releaseId"])
            imutable = generated["contracts"]["ImutableUnivocity"]
            golden_imutable = golden["contracts"]["ImutableUnivocity"]
            self.assertEqual(
                imutable["creationBytecode"], golden_imutable["creationBytecode"]
            )
            self.assertEqual(
                imutable["bytecodeSha256"], golden_imutable["bytecodeSha256"]
            )

    def test_main_includes_uups_entries_when_artifacts_present(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            for name in ("UUPSUnivocity", "ERC1967Proxy"):
                artifact_dir = out_dir / f"{name}.sol"
                artifact_dir.mkdir(parents=True)
                (artifact_dir / f"{name}.json").write_text(
                    json.dumps(
                        {
                            "bytecode": {"object": "0x6003"},
                            "metadata": json.dumps(
                                {"compiler": {"version": "0.8.26+commit.abc"}}
                            ),
                            "abi": [{"type": "constructor", "inputs": []}],
                        }
                    ),
                    encoding="utf-8",
                )
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
            output = Path(tmp) / "deploy-manifest-v0.4.0.json"
            self.assertEqual(
                main(
                    [
                        "v0.4.0",
                        "--out-dir",
                        str(out_dir),
                        "--output",
                        str(output),
                    ]
                ),
                0,
            )
            generated = json.loads(output.read_text(encoding="utf-8"))
            contracts = generated["contracts"]
            self.assertIn("UUPSUnivocity", contracts)
            self.assertIn("ERC1967Proxy", contracts)
            self.assertIn("abi", contracts["UUPSUnivocity"])


if __name__ == "__main__":
    unittest.main()
