#!/usr/bin/env python3
"""Check the core dependency lock or emit a path-free CycloneDX SBOM."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from importlib import metadata
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "provenance" / "dependency-lock.json"
NAME_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")


def _normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _installed() -> dict[str, str]:
    installed = {
        _normalise(dist.metadata["Name"]): dist.version
        for dist in metadata.distributions()
        if dist.metadata.get("Name")
    }
    configured = os.environ.get("APEX_ANALYSIS_PYTHON", "").strip()
    if configured:
        executable = Path(configured).expanduser()
        if executable.is_file():
            prefix = executable.parent.parent
            candidates = sorted(prefix.glob("lib/python*/site-packages"))
            candidates.append(prefix / "Lib" / "site-packages")
            for site_packages in candidates:
                if not site_packages.is_dir():
                    continue
                installed.update(
                    {
                        _normalise(dist.metadata["Name"]): dist.version
                        for dist in metadata.distributions(path=[str(site_packages)])
                        if dist.metadata.get("Name")
                    }
                )
                break
    return installed


def _load_lock(lock: Path = LOCK) -> dict[str, object]:
    try:
        record = json.loads(lock.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("dependency lock is missing or invalid") from exc
    if record.get("schema") != "apex-reverse-engineering/dependency-lock-v1":
        raise ValueError("unsupported dependency lock")
    if not isinstance(record.get("requirements"), dict) or not isinstance(record.get("packages"), list) or not isinstance(record.get("lock_files", {}), dict):
        raise ValueError("dependency lock has an invalid shape")
    return record


def _root_file(relative_name: str) -> Path:
    candidate = (ROOT / relative_name).resolve()
    if candidate != ROOT and ROOT not in candidate.parents:
        raise ValueError("dependency lock contains a path outside the skill directory")
    return candidate


def check_lock(lock: Path = LOCK) -> dict[str, object]:
    record = _load_lock(lock)
    installed = _installed()
    requirement_checks = []
    for filename, entry in record["requirements"].items():
        if not isinstance(filename, str):
            raise ValueError("dependency lock contains an invalid requirements filename")
        requirement_path = _root_file(filename)
        expected_hash = entry.get("sha256") if isinstance(entry, dict) else None
        actual_hash = _sha256(requirement_path) if requirement_path.is_file() else None
        requirement_checks.append({"file": filename, "role": entry.get("role") if isinstance(entry, dict) else None, "hash_matches": actual_hash == expected_hash})

    package_checks = []
    for package in record["packages"]:
        if not isinstance(package, dict) or not isinstance(package.get("name"), str) or not isinstance(package.get("version"), str):
            raise ValueError("dependency lock contains an invalid package")
        key = _normalise(package["name"])
        actual = installed.get(key)
        package_checks.append({
            "name": package["name"],
            "locked_version": package["version"],
            "installed_version": actual,
            "matches": actual == package["version"],
            "role": package.get("role", "core"),
        })
    optional_checks = []
    optional_lock = record.get("optional_lock", {})
    optional_lock_file_check = None
    if isinstance(optional_lock, dict) and isinstance(optional_lock.get("file"), str):
        optional_lock_path = _root_file(optional_lock["file"])
        actual_hash = _sha256(optional_lock_path) if optional_lock_path.is_file() else None
        optional_lock_file_check = {
            "file": optional_lock["file"],
            "hash_matches": actual_hash == optional_lock.get("sha256"),
            "hashes": optional_lock.get("hashes") is True,
        }
    for package in optional_lock.get("packages", []) if isinstance(optional_lock, dict) else []:
        if not isinstance(package, dict) or not isinstance(package.get("name"), str) or not isinstance(package.get("version"), str):
            raise ValueError("optional dependency lock contains an invalid package")
        actual = installed.get(_normalise(package["name"]))
        optional_checks.append({
            "name": package["name"],
            "locked_version": package["version"],
            "installed_version": actual,
            "matches": actual == package["version"],
        })
    lock_file_checks = []
    for filename, entry in record.get("lock_files", {}).items():
        if not isinstance(filename, str) or not isinstance(entry, dict):
            raise ValueError("dependency lock contains an invalid lock-file entry")
        lock_path = _root_file(filename)
        expected_hash = entry.get("sha256")
        actual_hash = _sha256(lock_path) if lock_path.is_file() else None
        lock_file_checks.append({
            "file": filename,
            "role": entry.get("role"),
            "hashes": entry.get("hashes") is True,
            "hash_matches": actual_hash == expected_hash,
        })
    core_failures = [item for item in requirement_checks if item["role"] == "core" and not item["hash_matches"]]
    core_failures.extend(item for item in lock_file_checks if item["role"] == "core" and (not item["hash_matches"] or not item["hashes"])
    )
    core_failures.extend(item for item in package_checks if item["role"] == "core" and not item["matches"])
    unresolved_optional = set(record.get("optional_unresolved", []))
    unresolved_optional.update(item["name"] for item in optional_checks if not item["matches"])
    if optional_lock_file_check is not None and not optional_lock_file_check["hash_matches"]:
        unresolved_optional.add(str(optional_lock_file_check["file"]) + ":lock-hash")
    return {
        "schema": "apex-reverse-engineering/dependency-lock-check-v1",
        "status": "ready" if not core_failures else "failed",
        "core_failures": core_failures,
        "requirements": requirement_checks,
        "lock_files": lock_file_checks,
        "packages": package_checks,
        "optional_packages": optional_checks,
        "optional_lock_file": optional_lock_file_check,
        "optional_unresolved": sorted(unresolved_optional),
    }


def build_sbom(lock: Path = LOCK) -> dict[str, object]:
    record = _load_lock(lock)
    components = []
    for package in record["packages"]:
        if not isinstance(package, dict):
            raise ValueError("dependency lock contains an invalid package")
        name = package["name"]
        version = package["version"]
        components.append({
            "type": "library",
            "name": name,
            "version": version,
            "purl": f"pkg:pypi/{_normalise(name)}@{version}",
            "scope": "optional" if package.get("role") == "optional" else "required",
        })
    components.sort(key=lambda item: (item["name"].lower(), item["version"]))
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"component": {"type": "application", "name": "apex-reverse-engineering-skill", "version": "local"}},
        "components": components,
        "properties": [
            {"name": "apex:lock-schema", "value": str(record["schema"])},
            {"name": "apex:optional-unresolved-count", "value": str(len(record.get("optional_unresolved", [])))},
        ],
    }


def _write_once(path: Path, payload: dict[str, object]) -> None:
    path = path.expanduser().resolve()
    if path.exists():
        raise ValueError(f"refusing to overwrite existing report: {path.name}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check-lock", "sbom"))
    parser.add_argument("--output", type=Path, default=None, help="Write SBOM once instead of printing it")
    args = parser.parse_args()
    try:
        if args.action == "check-lock":
            result = check_lock()
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0 if result["status"] == "ready" else 1
        result = build_sbom()
        if args.output is None:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            _write_once(args.output, result)
            print(json.dumps({"schema": "CycloneDX", "written": True, "component_count": len(result["components"])}, sort_keys=True))
        return 0
    except (OSError, ValueError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
