"""Tests for update_deployment_release_entry.py."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "update_deployment_release_entry.py"


class UpdateDeploymentReleaseEntryTest(unittest.TestCase):
    def test_upserts_version_and_channel(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            deployment = Path(tmp) / "deployment.json"
            deployment.write_text(
                json.dumps(
                    {
                        "schemaVersion": "v1",
                        "shared": {},
                        "environments": {},
                        "releases": [],
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    str(deployment),
                    "--version",
                    "v0.1.4",
                    "--channel",
                    "dev",
                    "--ks256-address",
                    "0x6055f9615Edc5b4B7d8C87c75E1B5EE45583492C",
                ],
                check=True,
            )
            data = json.loads(deployment.read_text(encoding="utf-8"))
            self.assertEqual(
                data["releases"],
                [
                    {
                        "version": "v0.1.4",
                        "channel": "dev",
                        "ks256Address": "0x6055f9615Edc5b4B7d8C87c75E1B5EE45583492C",
                    }
                ],
            )


if __name__ == "__main__":
    unittest.main()
