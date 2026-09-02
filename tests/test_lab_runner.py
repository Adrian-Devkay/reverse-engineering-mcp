from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from isolated_runner import build_runtime_command, redact_output, run_lab  # noqa: E402


class LabRunnerTests(unittest.TestCase):
    def test_runtime_command_has_fixed_isolation_guards(self) -> None:
        image = "example@sha256:" + "a" * 64
        command = build_runtime_command("docker", image, Path("/case"), ["/case/sample"])
        for required in ("--pull=never", "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges=true", "--user=65532:65532"):
            self.assertIn(required, command)
        self.assertNotIn("sh", command)
        self.assertNotIn("bash", command)

    def test_output_redaction_is_bounded(self) -> None:
        text, truncated = redact_output(b"Authorization: Bearer abc123\n/home/user/private", Path("/tmp/case"))
        self.assertNotIn("abc123", text)
        self.assertIn("[REDACTED]", text)
        self.assertIn("<redacted-path>", text)
        self.assertFalse(truncated)

    def test_tagged_image_is_rejected_before_runtime_use(self) -> None:
        with self.assertRaises(ValueError):
            run_lab(Path("/tmp/does-not-matter"), "sample.bin", "docker", "example:latest", "native", [], 5, False)


if __name__ == "__main__":
    unittest.main()
