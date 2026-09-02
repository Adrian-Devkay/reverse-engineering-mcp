#!/usr/bin/env python3
"""Create a non-destructive, scope-first manifest for an authorized web case."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def normalize_domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    if not domain or "://" in domain or "/" in domain or "@" in domain:
        raise ValueError("scope must be a hostname or IP address, without scheme, path, port, or credentials")
    try:
        return domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("scope is not a valid hostname") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case_dir", type=Path, help="Dedicated directory for the web case")
    parser.add_argument("--authorization", required=True, help="Plain-language authorization basis; do not include secrets")
    parser.add_argument("--scope", action="append", required=True, help="Authorized hostname or IP; may be repeated")
    parser.add_argument("--exclusion", action="append", default=[], help="Explicitly excluded target or technique; may be repeated")
    args = parser.parse_args()

    if not args.authorization.strip():
        parser.error("authorization must not be empty")
    try:
        scopes = sorted({normalize_domain(item) for item in args.scope})
    except ValueError as exc:
        parser.error(str(exc))

    case_dir = args.case_dir.expanduser().resolve()
    case_dir.mkdir(parents=True, exist_ok=True)
    output = case_dir / "web-case.json"
    if output.exists():
        parser.error(f"refusing to overwrite existing web manifest: {output}")

    record = {
        "schema": "apex-reverse-engineering/web-case-v1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "scope": {
            "authorization": args.authorization.strip(),
            "allowed_domains": scopes,
            "exclusions": args.exclusion,
        },
        "network_policy": {
            "methods": ["GET"],
            "robots": "respect",
            "credentials": False,
            "cookies": False,
            "allow_ignore_robots": False,
            "allow_private_network": False,
            "allow_nonstandard_port": False,
            "default_max_pages": 100,
            "default_max_depth": 2,
            "default_max_response_bytes": 1_048_576,
            "default_max_total_bytes": 33_554_432,
        },
        "actions": [],
        "findings": [],
    }
    output.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
