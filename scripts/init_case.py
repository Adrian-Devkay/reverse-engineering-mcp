#!/usr/bin/env python3
"""Create a deterministic, hash-first reverse-engineering case manifest."""

import argparse
import hashlib
import json
import platform
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path, help="Existing artifact to hash; it is never modified")
    parser.add_argument("case_dir", type=Path, help="New or existing directory for case.json")
    parser.add_argument("--case-id", help="Stable case identifier; defaults to a name derived from the artifact hash")
    parser.add_argument("--authorization", default="TO_BE_CONFIRMED", help="Authorization basis recorded in the local manifest")
    parser.add_argument("--analyst", default="UNSPECIFIED", help="Analyst label recorded in the local manifest")
    parser.add_argument("--exclude", action="append", default=[], help="Excluded surface; may be supplied more than once")
    args = parser.parse_args()

    artifact = args.artifact.expanduser().resolve()
    case_dir = args.case_dir.expanduser().resolve()
    if not artifact.is_file():
        parser.error(f"artifact is not a regular file: {artifact}")
    mode = artifact.stat().st_mode
    if not stat.S_ISREG(mode):
        parser.error(f"artifact is not a regular file: {artifact}")

    digest = sha256_file(artifact)
    case_id = args.case_id or f"case-{artifact.stem}-{digest[:12]}"
    case_dir.mkdir(parents=True, exist_ok=True)
    record = {
        "schema": "reverse-engineering-mcp/case-v1",
        "case_id": case_id,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "scope": {"authorization": args.authorization, "target": str(artifact), "exclusions": args.exclude},
        "analyst": args.analyst,
        "artifact": {
            "path": str(artifact),
            "size_bytes": artifact.stat().st_size,
            "sha256": digest,
            "mtime_utc": datetime.fromtimestamp(artifact.stat().st_mtime, timezone.utc).isoformat(),
        },
        "environment": {"platform": platform.platform(), "python": sys.version.split()[0]},
        "actions": [],
        "findings": [],
    }
    output = case_dir / "case.json"
    if output.exists():
        parser.error(f"refusing to overwrite existing manifest: {output}")
    output.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
