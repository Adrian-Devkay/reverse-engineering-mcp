from __future__ import annotations

import unittest
import sys
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from toolchain_registry import TOOLCHAIN_REGISTRY, probe_toolchain


class ToolchainRegistryTests(unittest.TestCase):
    def test_registry_has_static_and_isolation_gated_backends(self) -> None:
        by_id = {item["id"]: item for item in TOOLCHAIN_REGISTRY}
        self.assertEqual(by_id["gnu-binutils"]["adapter"], "mcp_static")
        self.assertEqual(by_id["ghidra"]["adapter"], "probe_only")
        self.assertTrue(by_id["frida"]["requires_isolation"])
        self.assertTrue(by_id["aflplusplus"]["requires_isolation"])
        self.assertEqual(by_id["pyelftools"]["python_modules"], ("elftools",))
        self.assertTrue(by_id["unicorn"]["requires_isolation"])

    def test_probe_is_deterministic_and_does_not_expose_paths(self) -> None:
        def command_lookup(name: str):
            return "/synthetic/bin/" + name if name in {"file", "analyzeHeadless"} else None

        result = probe_toolchain(command_lookup=command_lookup, module_lookup=lambda name: name == "lief")
        self.assertEqual(result["schema"], "apex-reverse-engineering/toolchain-v1")
        self.assertTrue(result["paths_redacted"])
        self.assertNotIn("/synthetic/bin", str(result))
        by_id = {item["id"]: item for item in result["tools"]}
        self.assertTrue(by_id["gnu-binutils"]["available"])
        self.assertTrue(by_id["ghidra"]["available"])
        self.assertTrue(by_id["lief"]["available"])
        self.assertFalse(by_id["frida"]["available"])

    def test_external_analysis_environment_requires_explicit_configuration(self) -> None:
        previous = os.environ.pop("APEX_ANALYSIS_PYTHON", None)
        try:
            result = probe_toolchain(command_lookup=lambda name: None, module_lookup=lambda name: False)
            self.assertFalse(result["external_analysis_environment_configured"])
        finally:
            if previous is not None:
                os.environ["APEX_ANALYSIS_PYTHON"] = previous


if __name__ == "__main__":
    unittest.main()
