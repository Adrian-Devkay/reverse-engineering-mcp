#!/usr/bin/env python3
"""Probe optional reverse-engineering tools without revealing local paths."""

from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from toolchain_registry import probe_toolchain  # noqa: E402


def main() -> int:
    print(json.dumps(probe_toolchain(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
