import json
import subprocess
import sys
from pathlib import Path


def test_init_case_writes_hash_first_manifest(tmp_path):
    artifact = tmp_path / "sample.bin"
    case_dir = tmp_path / "case"
    artifact.write_bytes(b"sample")
    script = Path(__file__).parents[1] / "scripts" / "init_case.py"

    result = subprocess.run(
        [
            sys.executable,
            str(script),
            str(artifact),
            str(case_dir),
            "--case-id",
            "case-test",
            "--authorization",
            "owner-approved",
            "--analyst",
            "test",
            "--exclude",
            "external-network",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    record = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
    assert result.stdout.strip().endswith("case.json")
    assert record["schema"] == "reverse-engineering-mcp/case-v1"
    assert record["case_id"] == "case-test"
    assert record["scope"]["authorization"] == "owner-approved"
    assert record["scope"]["exclusions"] == ["external-network"]
    assert len(record["artifact"]["sha256"]) == 64
