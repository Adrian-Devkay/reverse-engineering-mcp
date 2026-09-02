from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INIT_CASE = ROOT / "scripts" / "init_case.py"
INIT_WEB_CASE = ROOT / "scripts" / "init_web_case.py"
WEB_RECON = ROOT / "scripts" / "web_recon.py"
MCP_SERVER = ROOT / "mcp_server.py"


class SkillIntegrityTests(unittest.TestCase):
    def test_mcp_is_fail_closed_and_redacts_paths_by_default(self) -> None:
        source = MCP_SERVER.read_text(encoding="utf-8")
        self.assertIn("DEFAULT_ROOTS: tuple[Path, ...] = ()", source)
        self.assertIn("APEX_MCP_ALLOWED_ROOTS must be configured", source)
        self.assertIn("APEX_MCP_REVEAL_PATHS", source)
        self.assertIn("from toolchain_registry import probe_toolchain", source)
        self.assertIn("def apex_static_tool", source)
        self.assertIn("shell=False", source)
        self.assertIn("start_new_session=True", source)

        lab_source = (ROOT / "scripts" / "isolated_runner.py").read_text(encoding="utf-8")
        self.assertIn('"--network=none"', lab_source)
        self.assertIn('"--pull=never"', lab_source)
        self.assertIn('"--read-only"', lab_source)
        self.assertIn('"--execution-approved"', lab_source)
        self.assertNotIn("allow-tagged-image", lab_source)
        self.assertNotIn("allow_tagged_image", lab_source)

    def test_case_requires_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifact = root / "sample.bin"
            artifact.write_bytes(b"synthetic sample")
            case_dir = root / "case"
            result = subprocess.run(
                [sys.executable, str(INIT_CASE), str(artifact), str(case_dir)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("authorization", result.stderr.lower())

    def test_case_records_authorization_and_refuses_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifact = root / "sample.bin"
            artifact.write_bytes(b"synthetic sample")
            case_dir = root / "case"
            command = [
                sys.executable,
                str(INIT_CASE),
                str(artifact),
                str(case_dir),
                "--authorization",
                "local synthetic test fixture",
                "--exclusion",
                "external network",
            ]
            first = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(first.returncode, 0, first.stderr)
            record = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
            self.assertEqual(record["scope"]["authorization"], "local synthetic test fixture")
            self.assertEqual(record["scope"]["exclusions"], ["external network"])

            second = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertNotEqual(second.returncode, 0)
            self.assertIn("refusing to overwrite", second.stderr.lower())

    def test_web_case_requires_scope_and_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            case_dir = Path(temp_dir) / "web-case"
            missing_auth = subprocess.run(
                [sys.executable, str(INIT_WEB_CASE), str(case_dir), "--scope", "example.test"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(missing_auth.returncode, 0)
            self.assertIn("authorization", missing_auth.stderr.lower())

            created = subprocess.run(
                [
                    sys.executable,
                    str(INIT_WEB_CASE),
                    str(case_dir),
                    "--authorization",
                    "local synthetic web fixture",
                    "--scope",
                    "example.test",
                    "--exclusion",
                    "credentials",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(created.returncode, 0, created.stderr)
            record = json.loads((case_dir / "web-case.json").read_text(encoding="utf-8"))
            self.assertEqual(record["schema"], "apex-reverse-engineering/web-case-v1")
            self.assertEqual(record["scope"]["allowed_domains"], ["example.test"])
            self.assertFalse(record["network_policy"]["credentials"])

    def test_web_recon_has_network_and_privacy_gates(self) -> None:
        source = WEB_RECON.read_text(encoding="utf-8")
        self.assertIn("only http and https URLs are allowed", source)
        self.assertIn("credentials in URLs are not allowed", source)
        self.assertIn('"method": "GET"', source)
        self.assertIn("private, loopback, link-local, reserved, or non-global destinations are blocked", source)
        self.assertIn("MAX_TOTAL_BYTES", source)
        self.assertIn("refusing to overwrite existing report", source)


if __name__ == "__main__":
    unittest.main()
