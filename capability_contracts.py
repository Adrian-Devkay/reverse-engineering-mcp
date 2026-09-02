"""Evidence contracts used to measure capability readiness honestly."""

from __future__ import annotations


CAPABILITY_CONTRACTS: tuple[dict[str, object], ...] = (
    {
        "id": "authorization",
        "label": "Authorization and scope",
        "target_score": 9,
        "evidence": ("plain-language authorization", "explicit exclusions", "time/network boundary", "stop condition"),
    },
    {
        "id": "evidence",
        "label": "Evidence and reproducibility",
        "target_score": 9,
        "evidence": ("artifact hash", "tool/version record", "preserved commands", "observed/inferred/unknown labels"),
    },
    {
        "id": "privacy",
        "label": "Privacy and redaction",
        "target_score": 9,
        "evidence": ("redacted paths", "redacted URLs", "no credentials/cookies", "bounded output"),
    },
    {
        "id": "static_core",
        "label": "Native static triage",
        "target_score": 9,
        "evidence": ("format and architecture", "sections/symbols", "strings/entropy", "disassembly cross-check"),
    },
    {
        "id": "static_deep",
        "label": "Deep static analysis",
        "target_score": 9,
        "evidence": ("function recovery", "decompilation", "call graph", "cross-reference/data-flow corroboration"),
    },
    {
        "id": "program_reasoning",
        "label": "Symbolic and emulated reasoning",
        "target_score": 9,
        "evidence": ("bounded state space", "path assumptions", "concrete corroboration", "resource limits"),
    },
    {
        "id": "dynamic",
        "label": "Dynamic observation",
        "target_score": 9,
        "evidence": ("isolated lab", "no-network policy", "trace/log capture", "revertible snapshot"),
    },
    {
        "id": "fuzzing",
        "label": "Fuzzing and memory safety",
        "target_score": 9,
        "evidence": ("harness contract", "seed/corpus provenance", "sanitizer signal", "minimized crash and deduplication"),
    },
    {
        "id": "malware",
        "label": "Malware and suspicious-code analysis",
        "target_score": 9,
        "evidence": ("offline specimen hash", "behavior timeline", "IOC validation", "containment guidance"),
    },
    {
        "id": "access_control",
        "label": "Authentication, IDOR, and privilege boundaries",
        "target_score": 9,
        "evidence": ("actor/tenant/resource/action matrix", "denied control", "source-to-sink predicate", "safe differential test"),
    },
    {
        "id": "web_recon",
        "label": "Authorized web reconnaissance",
        "target_score": 9,
        "evidence": ("web manifest", "exact scope", "robots decision", "redacted response hashes and links"),
    },
    {
        "id": "protocol",
        "label": "Protocol and file-format reasoning",
        "target_score": 9,
        "evidence": ("authorized specimens", "grammar/state model", "differential pairs", "bounded parser test"),
    },
    {
        "id": "firmware",
        "label": "Firmware and embedded analysis",
        "target_score": 9,
        "evidence": ("partition/boot chain", "update trust", "emulation limits", "recovery plan"),
    },
    {
        "id": "crypto_supply_chain",
        "label": "Crypto, update, and supply-chain trust",
        "target_score": 9,
        "evidence": ("trust decision", "key/material lifecycle", "provenance", "reachability and deployment mapping"),
    },
    {
        "id": "source_dataflow",
        "label": "Source analysis and data flow",
        "target_score": 9,
        "evidence": ("commit identity", "source-to-sink trace", "dependency provenance", "regression test"),
    },
    {
        "id": "mobile_managed",
        "label": "Mobile and managed-code analysis",
        "target_score": 9,
        "evidence": ("package/signing record", "permission/IPC map", "native bridge", "server-assumption boundary"),
    },
    {
        "id": "cve_src",
        "label": "CVE and SRC-quality reporting",
        "target_score": 9,
        "evidence": ("reachability verdict", "safe reproducer", "impact", "limitations and remediation"),
    },
)
