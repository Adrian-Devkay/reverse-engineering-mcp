from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from isolated_runner import _resolve_artifact  # noqa: E402
from mcp_server import _parse  # noqa: E402
from web_recon import _safe_headers  # noqa: E402


class HardeningTests(unittest.TestCase):
    def test_native_binary_parser_returns_process_safe_summary(self) -> None:
        executable = shutil.which("true")
        if executable is None:
            self.skipTest("no benign ELF fixture available")
        parsed = _parse(Path(executable))
        self.assertIsInstance(parsed, dict)
        self.assertIn("sections", parsed)
        self.assertIn("exports", parsed)

    def test_native_binary_parser_failure_is_contained(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = Path(temp_dir) / "malformed.bin"
            artifact.write_bytes(b"not a supported binary")
            with self.assertRaisesRegex(ValueError, "invalid or unsupported binary"):
                _parse(artifact)

    def test_runner_rejects_changed_artifact_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            case_dir = Path(temp_dir)
            artifact = case_dir / "sample.bin"
            artifact.write_bytes(b"changed")
            case = {
                "artifact": {
                    "path": str(artifact),
                    "size_bytes": len(b"original"),
                    "sha256": hashlib.sha256(b"original").hexdigest(),
                }
            }
            with self.assertRaisesRegex(ValueError, "does not match"):
                _resolve_artifact(case_dir, case, "sample.bin")

    def test_location_header_query_values_are_redacted(self) -> None:
        headers = _safe_headers({"Location": "https://example.test/reset?token=secret"})
        self.assertNotIn("secret", headers["location"])
        self.assertIn("REDACTED", headers["location"])

    def test_web_exceptions_require_manifest_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            case_dir = Path(temp_dir)
            (case_dir / "web-case.json").write_text(
                json.dumps(
                    {
                        "schema": "apex-reverse-engineering/web-case-v1",
                        "scope": {"authorization": "synthetic test", "allowed_domains": ["example.test"]},
                        "network_policy": {
                            "allow_ignore_robots": False,
                            "allow_private_network": False,
                            "allow_nonstandard_port": False,
                        },
                    }
                ),
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "web_recon.py"), str(case_dir), "https://example.test/", "--allow-private-network"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("not authorized by web-case.json", result.stderr)


if __name__ == "__main__":
    unittest.main()
