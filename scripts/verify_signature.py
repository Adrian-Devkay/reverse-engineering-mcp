#!/usr/bin/env python3
"""Verify a detached OpenSSL signature using a supplied public-key trust anchor."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "provenance" / "source-manifest.json"


def _regular_file(value: str) -> Path:
    raw_path = Path(value).expanduser()
    if raw_path.is_symlink():
        raise ValueError("signature inputs must not be symbolic links")
    path = raw_path.resolve(strict=True)
    if not path.is_file():
        raise ValueError("signature inputs must be regular files")
    return path


def verify_signature(manifest: Path, signature: Path, public_key: Path, algorithm: str = "digest-sha256") -> dict[str, object]:
    openssl = shutil.which("openssl")
    if not openssl:
        raise ValueError("openssl is required for signature verification")
    if algorithm == "digest-sha256":
        command = [openssl, "dgst", "-sha256", "-verify", str(public_key), "-signature", str(signature), str(manifest)]
    elif algorithm == "pkeyutl":
        command = [openssl, "pkeyutl", "-verify", "-pubin", "-inkey", str(public_key), "-sigfile", str(signature), "-in", str(manifest)]
    else:
        raise ValueError("unsupported signature algorithm")
    result = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=ROOT,
        env={"PATH": os.path.dirname(openssl), "LC_ALL": "C", "LANG": "C"},
        shell=False,
        timeout=10,
        check=False,
    )
    return {
        "schema": "apex-reverse-engineering/signature-verification-v1",
        "tool": "openssl",
        "algorithm": algorithm,
        "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
        "valid": result.returncode == 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--algorithm", choices=("digest-sha256", "pkeyutl"), default="digest-sha256")
    args = parser.parse_args()
    try:
        result = verify_signature(_regular_file(str(args.manifest)), _regular_file(str(args.signature)), _regular_file(str(args.public_key)), args.algorithm)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
