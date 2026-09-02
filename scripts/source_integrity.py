#!/usr/bin/env python3
"""Create or verify a path-stable SHA-256 manifest for this skill tree."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "provenance" / "source-manifest.json"
SKIP_DIRECTORIES = {".git", ".venv", "__pycache__"}
SKIP_FILES = {"source-manifest.json", "source-manifest.sig"}


def _manifest_path(value: str | None) -> Path:
    candidate = DEFAULT_MANIFEST if value is None else Path(value).expanduser()
    if not candidate.is_absolute():
        candidate = ROOT / candidate
    candidate = candidate.resolve()
    if candidate != ROOT and ROOT not in candidate.parents:
        raise ValueError("manifest must be inside the skill directory")
    return candidate


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _files(manifest: Path) -> list[Path]:
    result: list[Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(ROOT)
        if any(part in SKIP_DIRECTORIES for part in relative.parts):
            continue
        if path == manifest or path.name in SKIP_FILES:
            continue
        result.append(path)
    return sorted(result, key=lambda item: item.relative_to(ROOT).as_posix())


def build_manifest(manifest: Path = DEFAULT_MANIFEST) -> dict[str, object]:
    entries = []
    for path in _files(manifest):
        relative = path.relative_to(ROOT).as_posix()
        entries.append({"path": relative, "size_bytes": path.stat().st_size, "sha256": _sha256(path)})
    return {
        "schema": "apex-reverse-engineering/source-manifest-v1",
        "algorithm": "sha256",
        "root": "skill-directory",
        "files": entries,
    }


def _valid_relative_path(value: object) -> bool:
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        return False
    return ".." not in Path(value).parts


def verify_manifest(manifest: Path = DEFAULT_MANIFEST) -> dict[str, object]:
    try:
        record = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("source manifest is missing or invalid") from exc
    if (
        record.get("schema") != "apex-reverse-engineering/source-manifest-v1"
        or record.get("algorithm") != "sha256"
        or record.get("root") != "skill-directory"
        or not isinstance(record.get("files"), list)
    ):
        raise ValueError("unsupported source manifest")

    expected: dict[str, tuple[int, str]] = {}
    for entry in record["files"]:
        if not isinstance(entry, dict) or not _valid_relative_path(entry.get("path")):
            raise ValueError("source manifest contains an invalid relative path")
        path = entry["path"]
        if path in expected or not isinstance(entry.get("size_bytes"), int) or not isinstance(entry.get("sha256"), str):
            raise ValueError("source manifest contains an invalid or duplicate entry")
        expected[path] = (entry["size_bytes"], entry["sha256"])

    actual = {
        path.relative_to(ROOT).as_posix(): (path.stat().st_size, _sha256(path))
        for path in _files(manifest)
    }
    missing = sorted(set(expected) - set(actual))
    unexpected = sorted(set(actual) - set(expected))
    changed = sorted(path for path in set(expected) & set(actual) if expected[path] != actual[path])
    valid = not missing and not unexpected and not changed
    return {
        "schema": "apex-reverse-engineering/source-verification-v1",
        "valid": valid,
        "file_count": len(actual),
        "missing": missing,
        "unexpected": unexpected,
        "changed": changed,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    create = subparsers.add_parser("create", help="write a new source manifest")
    create.add_argument("--manifest", type=str, default=None)
    verify = subparsers.add_parser("verify", help="verify the current source tree")
    verify.add_argument("--manifest", type=str, default=None)
    args = parser.parse_args()

    try:
        manifest = _manifest_path(args.manifest)
        if args.action == "create":
            if manifest.exists():
                parser.error(f"refusing to overwrite existing source manifest: {manifest.name}")
            manifest.parent.mkdir(parents=True, exist_ok=True)
            manifest.write_text(json.dumps(build_manifest(manifest), indent=2) + "\n", encoding="utf-8")
            print(json.dumps({"schema": "apex-reverse-engineering/source-manifest-v1", "created": True, "file_count": len(build_manifest(manifest)["files"])}, sort_keys=True))
            return 0

        result = verify_manifest(manifest)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["valid"] else 1
    except (OSError, ValueError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
