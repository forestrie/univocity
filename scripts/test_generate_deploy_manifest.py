"""Tests for scripts/generate_deploy_manifest.py."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from generate_deploy_manifest import bytecode_sha256, contract_entry


class GenerateDeployManifestTest(unittest.TestCase):
    def test_bytecode_sha256_known_vector(self) -> None:
        digest = bytecode_sha256("0x6001")
        self.assertEqual(len(digest), 64)

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


if __name__ == "__main__":
    unittest.main()
