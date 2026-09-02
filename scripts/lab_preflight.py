#!/usr/bin/env python3
"""Check for isolated lab runtimes without executing a sample or revealing paths."""

from __future__ import annotations

import json
import shutil


ISOLATION_BACKENDS = (
    {"id": "docker", "command": "docker", "network_isolation": True, "read_only_mounts": True},
    {"id": "podman", "command": "podman", "network_isolation": True, "read_only_mounts": True},
    {"id": "firejail", "command": "firejail", "network_isolation": True, "read_only_mounts": True},
    {"id": "bubblewrap", "command": "bwrap", "network_isolation": True, "read_only_mounts": True},
    {"id": "nsjail", "command": "nsjail", "network_isolation": True, "read_only_mounts": True},
)


def probe_lab() -> dict[str, object]:
    backends = []
    for spec in ISOLATION_BACKENDS:
        backends.append(
            {
                **spec,
                "available": bool(shutil.which(spec["command"])),
            }
        )
    container = next((item for item in backends if item["available"] and item["id"] in {"docker", "podman"}), None)
    return {
        "schema": "apex-reverse-engineering/lab-preflight-v1",
        "paths_redacted": True,
        "sample_executed": False,
        "recommended_container_runtime": container["id"] if container else None,
        "backends": backends,
    }


def main() -> int:
    print(json.dumps(probe_lab(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
