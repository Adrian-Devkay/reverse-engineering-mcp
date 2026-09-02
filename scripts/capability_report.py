#!/usr/bin/env python3
"""Report capability readiness from the local toolchain and isolation preflight."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from capability_contracts import CAPABILITY_CONTRACTS  # noqa: E402
from lab_preflight import probe_lab  # noqa: E402
from provenance_report import check_lock  # noqa: E402
from toolchain_registry import probe_toolchain  # noqa: E402


def _command_map(inventory: dict[str, object]) -> dict[str, bool]:
    return {
        name: available
        for tool in inventory["tools"]
        for name, available in tool["commands"].items()
    }


def _module_map(inventory: dict[str, object]) -> dict[str, bool]:
    return {
        name: available
        for tool in inventory["tools"]
        for name, available in tool["python_modules"].items()
    }


def _ready(command_map: dict[str, bool], module_map: dict[str, bool], *, commands=(), modules=()) -> bool:
    return all(command_map.get(name, False) for name in commands) and all(module_map.get(name, False) for name in modules)


def _module_exists(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ModuleNotFoundError, ValueError):
        return False


def build_report() -> dict[str, object]:
    inventory = probe_toolchain()
    lab = probe_lab()
    commands = _command_map(inventory)
    modules = _module_map(inventory)
    container_ready = lab["recommended_container_runtime"] is not None
    mcp_ready = _module_exists("mcp")
    static_core_ready = mcp_ready and _ready(commands, modules, modules=("lief", "capstone", "yara"))

    readiness: dict[str, tuple[int, str, tuple[str, ...]]] = {
        "authorization": (9, "bundled_contract", ()),
        "evidence": (8, "bundled_manifest_and_tests", ("case-specific evidence review",)),
        "privacy": (8, "bundled_redaction_controls", ("runtime report review",)),
        "static_core": (9 if static_core_ready else 4, "mcp_native", ("mcp/lief/capstone/yara" if not static_core_ready else "",)),
        "static_deep": (6 if any(commands.get(item, False) for item in ("analyzeHeadless", "rizin", "rz-bin", "retdec-decompiler")) else 3, "external_backend", ("Ghidra/Rizin/RetDec adapter" ,)),
        "program_reasoning": (6 if any(modules.get(item, False) for item in ("angr", "miasm")) else 3, "external_backend", ("angr or Miasm corroboration",)),
        "dynamic": (7 if container_ready and any(commands.get(item, False) for item in ("gdb", "lldb", "frida", "qemu-x86_64")) else 3, "isolated_runner", ("local Docker/Podman plus runtime backend",)),
        "fuzzing": (7 if container_ready and any(commands.get(item, False) for item in ("afl-fuzz", "honggfuzz")) else 3, "isolated_runner", ("fuzzer and approved harness",)),
        "malware": (7 if modules.get("yara", False) and container_ready else 6 if modules.get("yara", False) else 3, "static_plus_lab", ("isolated behavior trace",)),
        "access_control": (6, "methodology_and_safe_web_collector", ("authorized target and differential test",)),
        "web_recon": (8, "bundled_get_only_collector", ("browser-rendered and authenticated workflows are separate",)),
        "protocol": (6 if commands.get("tshark", False) or modules.get("scapy", False) else 4, "external_backend", ("authorized capture or synthetic fixture",)),
        "firmware": (6 if commands.get("binwalk", False) or modules.get("binwalk", False) else 4, "external_backend", ("emulation/hardware backend",)),
        "crypto_supply_chain": (6 if any(commands.get(item, False) for item in ("syft", "grype", "osv-scanner", "trivy")) else 5, "workflow_contract", ("deployment-specific provenance",)),
        "source_dataflow": (6 if commands.get("semgrep", False) or commands.get("joern", False) else 4, "external_backend", ("source tree and commit",)),
        "mobile_managed": (6 if commands.get("jadx", False) or commands.get("apktool", False) or commands.get("ilspycmd", False) or commands.get("ILSpy", False) else 4, "external_backend", ("package-specific backend",)),
        "cve_src": (7, "evidence_contract", ("case-specific reproduction and vendor policy",)),
    }

    capabilities = []
    for contract in CAPABILITY_CONTRACTS:
        score, basis, missing = readiness[contract["id"]]
        capabilities.append(
            {
                "id": contract["id"],
                "label": contract["label"],
                "target_score": contract["target_score"],
                "readiness_score": score,
                "status": "ready" if score >= 9 else "partial" if score >= 6 else "blocked",
                "basis": basis,
                "missing_or_scope_dependent": [item for item in missing if item],
                "evidence_contract": list(contract["evidence"]),
            }
        )
    try:
        provenance = check_lock()
    except (OSError, ValueError) as exc:
        provenance = {"status": "unavailable", "reason": str(exc)}
    return {
        "schema": "apex-reverse-engineering/capability-report-v1",
        "target_score": 9,
        "module_tiers": {
            "core": {"activation": "default", "network": "none", "execution": "static-only"},
            "optional_web": {"activation": "web-case.json plus explicit web_recon.py", "network": "bounded-get-only"},
            "optional_lab": {"activation": "case.json plus digest image plus execution approval", "network": "none"},
        },
        "provenance": provenance,
        "toolchain": inventory,
        "lab_preflight": lab,
        "capabilities": capabilities,
    }


def main() -> int:
    print(json.dumps(build_report(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
