from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import provenance_report  # noqa: E402
import source_integrity  # noqa: E402


class ProvenanceTests(unittest.TestCase):
    def test_lock_and_sbom_are_path_free_and_deterministic(self) -> None:
        lock = json.loads((ROOT / "provenance" / "dependency-lock.json").read_text(encoding="utf-8"))
        sbom = provenance_report.build_sbom()
        self.assertEqual(lock["schema"], "apex-reverse-engineering/dependency-lock-v1")
        self.assertEqual(sbom, provenance_report.build_sbom())
        encoded = json.dumps(sbom, sort_keys=True)
        self.assertNotIn("/home/", encoded)
        self.assertNotIn("/root/", encoded)
        self.assertGreaterEqual(len(sbom["components"]), 20)

    def test_source_manifest_detects_tampering_without_absolute_paths(self) -> None:
        original_root = source_integrity.ROOT
        original_default = source_integrity.DEFAULT_MANIFEST
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                (root / "provenance").mkdir()
                (root / "SKILL.md").write_text("synthetic skill\n", encoding="utf-8")
                manifest = root / "provenance" / "source-manifest.json"
                source_integrity.ROOT = root
                source_integrity.DEFAULT_MANIFEST = manifest
                manifest.write_text(json.dumps(source_integrity.build_manifest(manifest), indent=2) + "\n", encoding="utf-8")

                verified = source_integrity.verify_manifest(manifest)
                self.assertTrue(verified["valid"])
                self.assertNotIn(str(root), json.dumps(verified))

                (root / "SKILL.md").write_text("tampered\n", encoding="utf-8")
                changed = source_integrity.verify_manifest(manifest)
                self.assertFalse(changed["valid"])
                self.assertEqual(changed["changed"], ["SKILL.md"])
        finally:
            source_integrity.ROOT = original_root
            source_integrity.DEFAULT_MANIFEST = original_default


if __name__ == "__main__":
    unittest.main()
