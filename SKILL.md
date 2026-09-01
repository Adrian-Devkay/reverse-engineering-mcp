---
name: reverse-engineering-mcp
description: "Perform authorized, evidence-driven reverse engineering of binaries, apps, firmware, protocols, and malware with reproducible analysis and safe vulnerability triage."
---

# Reverse engineering-mcp

Use this skill when the user asks to understand, decompile, debug, instrument, compare, emulate, or document an existing binary, application, firmware image, protocol, file format, or malware sample. It is designed for advanced work, but it does not imply permission to access or modify a target.

## Operating contract

1. Establish scope before touching the target. Confirm that the sample, device, account, network, or service is owned by the user or covered by explicit authorization. If authorization or scope is unclear, ask for it and limit the response to a high-level plan.
2. Preserve evidence. Never alter the original artifact. Record SHA-256, size, timestamps, provenance, architecture, relevant tool versions, environment assumptions, and every material command or transformation. Use isolated copies and snapshots.
3. Select the smallest sufficient analysis mode. Read [references/modes.md](references/modes.md) when the target type or next technique is not obvious. Read [references/evidence.md](references/evidence.md) when producing a case record or report.
4. Work from hypotheses, not guesses: intake and triage, static analysis, controlled dynamic analysis, hypothesis testing, impact assessment, and reporting. Skip stages that add no evidence, but state what was not tested.
5. Prefer read-only, offline, and reversible actions. Do not contact external infrastructure, submit credentials, alter production systems, or execute an unknown sample outside an appropriately isolated lab.
6. Separate observation from inference. For each conclusion, cite the artifact, offset/address, trace, packet, log, or experiment that supports it; label confidence and unresolved alternatives.
7. Automate repeatable work where it improves reliability. Check whether tools are installed before relying on them, keep scripts deterministic, and save machine-readable outputs alongside human-readable notes.

## MCP routing

When available, use the local read-only MCP described in [references/mcp.md](references/mcp.md) for hash-first binary triage, sections, symbols, strings, and bounded byte previews. Treat MCP results as evidence, not conclusions; corroborate important claims with a second observation or an appropriate analyzer. Keep the MCP allowlist restricted to authorized case directories.

## Capability matrix

Treat every applicable layer below as a high-capability backend, while keeping the analysis bounded by authorization, evidence, and target format:

- Triage and corroboration: LIEF, Capstone, YARA, radare2, `file`, ELF/PE metadata, entropy, strings, and mitigations.
- Deep static analysis: Ghidra MCP with function recovery, decompilation, disassembly, call graphs, cross-references, namespaces, and byte-pattern search.
- Program reasoning: angr and Unicorn for bounded CFG, path, and emulation hypotheses; never treat symbolic output as proof without corroboration.
- Dynamic observation: GDB/gdbserver, Frida, and QEMU user-mode emulation in an isolated lab with explicit execution approval.
- Malware and suspicious-code triage: FLOSS, capa, YARA, controlled traces, configuration extraction, and indicator validation.
- Firmware and multi-architecture work: binwalk when available, partition/boot-chain inspection, QEMU/Unicorn emulation, and architecture-aware static cross-checks.
- Reproducibility: hash-first case manifests, pinned tool versions, preserved commands, offsets, traces, and machine-readable evidence.

“High capability” means the relevant backend is available and used appropriately; it does not mean an unknown sample is executed automatically or that a physical device can be modified without a separate authorization and recovery plan.

## Advanced analysis expectations

- Recover behavior across compiler optimizations, stripped symbols, packing, obfuscation, asynchronous control flow, and multiple architectures when applicable.
- Correlate static structure with runtime evidence: call graphs, data-flow, memory state, system calls, IPC, file changes, network traces, and configuration.
- For protocols and formats, infer grammars and state machines from differential observations; preserve captures and distinguish confirmed fields from hypotheses.
- For vulnerability work, explain root cause, reachability, affected conditions, safe validation, impact, and remediation. Prefer a non-destructive reproducer over a weaponized exploit.
- For firmware or hardware, document boot chain, partitions, update trust, debug interfaces, and emulation limitations; do not flash or modify a device without explicit authorization and a recovery path.
- For malware, extract behavior and indicators in a sandbox, avoid live command-and-control, and report containment and detection opportunities.

## Safety boundary

Decline or redirect requests whose primary purpose is unauthorized access, credential theft, persistence, evasion, destructive action, exfiltration, or bypassing access controls. When a dual-use technique is necessary for an authorized assessment, keep it scoped to the supplied target, use safe validation, and stop before deployment or operational abuse.

## Deliverable standard

Unless the user requests a different format, return:

- scope, authorization assumption, and target inventory;
- artifact hashes and analysis environment;
- method and evidence-backed findings;
- confidence, limitations, and unanswered questions;
- impact and prioritized remediation or detection guidance;
- an appendix of reproducible commands, scripts, offsets, traces, and tool outputs where safe to share.

Use [scripts/init_case.py](scripts/init_case.py) when a new case needs a deterministic artifact manifest. Do not create a case record for a target that has not passed the scope check.
