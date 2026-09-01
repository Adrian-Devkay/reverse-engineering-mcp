---
name: reverse-engineering-mcp
description: "Perform authorized, evidence-driven reverse engineering of binaries, apps, firmware, protocols, and malware with reproducible analysis and safe vulnerability triage."
---

# Reverse engineering-mcp

## Mission

Produce defensible reverse-engineering conclusions from authorized artifacts. The skill coordinates static analysis, controlled execution, emulation, instrumentation, protocol reasoning, vulnerability triage, and reporting while preserving evidence and avoiding operational abuse.

Use this skill when the user asks to understand, decompile, debug, instrument, compare, emulate, fuzz, or document an existing binary, application, firmware image, protocol, file format, or suspicious sample. It does not grant permission to access a target merely because the target is available.

## Non-negotiable operating contract

1. Establish scope before touching the target: owner or authorization basis, exact artifact/device/service, permitted techniques, time window, network limits, data handling, and stop conditions.
2. Preserve the original artifact. Work from a copy, record SHA-256 and size first, and retain provenance, timestamps, tool versions, transformations, and important commands.
3. Prefer offline, read-only, reversible analysis. Never submit credentials, contact real command-and-control infrastructure, alter production systems, or flash hardware during ordinary analysis.
4. Separate observations from inferences. Label claims as `Observed`, `Inferred`, or `Unknown`; cite offsets, addresses, traces, packets, logs, or repeatable experiments.
5. Use hypotheses and acceptance criteria. Every expensive or execution-capable action must answer a defined question and state what result would confirm or weaken the hypothesis.
6. Cross-check important conclusions with an independent view: decompiler versus assembly, static structure versus runtime trace, or format hypothesis versus differential input/output.
7. State coverage and limitations. A quiet trace, missing symbol, incomplete emulation, or non-reproduced crash is not proof of absence.

## Analysis lifecycle

Follow this lifecycle unless the user requests a narrower task. Read [references/workflow.md](references/workflow.md) for the detailed phase checklist.

### Phase 0: Scope gate

If authorization or scope is unclear, stop at a high-level plan. Do not create a case record, execute code, bypass access controls, contact a service, upload a sample, or alter a device until the missing boundary is resolved.

### Phase 1: Intake and integrity

Create a target inventory containing artifact name, source, format, architecture, size, SHA-256, timestamps, suspected runtime, and known exclusions. Use [scripts/init_case.py](scripts/init_case.py) for a deterministic manifest. Never place generated case data in the public repository.

### Phase 2: Triage

Identify file format, architecture, entry point, sections/segments, imports/exports, symbols, strings, entropy, compiler or packer clues, signing, and mitigation flags. Start with the local read-only MCP when available. Record both positive and negative observations.

### Phase 3: Static reconstruction

Recover functions, control flow, data flow, call graphs, cross-references, namespaces, types, resources, configuration, and trust boundaries. Treat decompiler output as a hypothesis. Confirm security-relevant paths against disassembly and raw bytes, especially parsers, deserializers, update logic, crypto/key handling, privilege transitions, IPC, and error paths.

### Phase 4: Hypothesis testing

Choose the least invasive technique that can discriminate between competing explanations. Use Capstone or radare2 for assembly corroboration, Ghidra for deep structure, angr/Unicorn for bounded reasoning, and differential specimens for protocols and formats. Preserve the exact inputs and expected observations.

### Phase 5: Controlled dynamic analysis

Use GDB/gdbserver, Frida, QEMU, or a sandbox only inside an isolated, revertible lab. Disable or simulate networking by default, remove credentials and sensitive mounts, snapshot before execution, and capture process, syscall, memory, file, IPC, and network evidence as appropriate. Dynamic execution requires explicit authorization for the sample and question.

### Phase 6: Correlation and triage

Build a source-to-behavior chain: input or trust boundary → parser/state transition → relevant function or instruction → observable effect → impact. For vulnerabilities, distinguish root cause, reachability, preconditions, exploitability, affected versions, impact, and remediation. Prefer a minimal non-destructive reproducer over a weaponized exploit.

### Phase 7: Reporting

Use [references/report-template.md](references/report-template.md) unless another format is requested. Include scope, integrity, environment, method, evidence table, confidence, limitations, impact, remediation/detection guidance, open questions, and safe reproduction details.

## Backend routing

Select the smallest sufficient set, then escalate when evidence is blocked:

| Question | Preferred backend | Required corroboration |
| --- | --- | --- |
| What is this file? | LIEF, `file`, read-only MCP | Hash and format metadata |
| What does this function do? | Ghidra MCP | Assembly, callers/callees, or data-flow |
| Where is a byte pattern or API used? | Ghidra search, radare2, YARA | Address and surrounding bytes |
| Can a path reach a condition? | angr or bounded Unicorn | Concrete constraints or a static path |
| What happens at runtime? | GDB, Frida, QEMU, sandbox | Reproducible trace and isolation record |
| Is code packed or obfuscated? | Entropy, FLOSS, capa, Ghidra, radare2 | Section layout, decoded strings, or behavior |
| Is a firmware image compound? | binwalk, strings, QEMU/Unicorn | Offsets, extracted hashes, and emulation limits |
| How does a protocol behave? | Controlled specimens, Scapy/boofuzz, differential tests | Preserved captures and state-machine evidence |

The local MCP described in [references/mcp.md](references/mcp.md) is deterministic and read-only. The Ghidra backend is for deep static analysis; its mutation tools require explicit approval and its project cache must remain separate from samples. Shell commands and execution-capable backends are fallback or hypothesis-testing surfaces, not substitutes for an evidence record.

## Evidence and confidence

For each material finding, maintain:

- **Claim:** one precise statement, not a bundle of assumptions.
- **Evidence:** file, hash, offset/address, trace, packet, log, or experiment identifier.
- **Interpretation:** why the evidence supports the claim.
- **Alternatives:** plausible explanations not ruled out.
- **Confidence:** high, medium, or low, with the reason.
- **Status:** confirmed, needs reproduction, blocked, or disproven.

Important findings should have two independent anchors when practical. Use [references/case-schema.md](references/case-schema.md) for the recommended machine-readable structure.

## Specialized modes

Read [references/modes.md](references/modes.md) and [references/tool-routing.md](references/tool-routing.md) when the target is not a straightforward native binary.

- **Malware or suspicious code:** quarantine first; extract capabilities, configuration, persistence, indicators, and behavior without live command-and-control.
- **Vulnerability analysis:** prove the unsafe boundary and reachability before discussing severity; do not infer remote exploitability from a suspicious instruction or an unverified crash.
- **Firmware and hardware:** document boot chain, partitions, update trust, debug interfaces, and recovery path; do not flash or change boot state without explicit authorization.
- **Protocols and file formats:** infer grammar and state transitions from controlled differential observations; mark guessed semantics as hypotheses.
- **Managed/mobile targets:** identify runtime, packaging, permissions, IPC, signing, exported components, storage, and native bridges before analyzing behavior.
- **Obfuscation and anti-analysis:** document the mechanism and its effect before neutralization; work on copies and preserve the original behavior.

## Execution and safety boundary

GDB/gdbserver, Frida, QEMU, fuzzers, and sandbox runners can execute target-controlled code even when used for observation. Require a disposable VM or equivalent isolation, a clean snapshot, disabled/simulated networking, no real credentials, and an explicit sample-specific authorization. Pause before external network access, production interaction, firmware flashing, authentication/licensing bypass, or exploit testing outside a local authorized lab.

Decline or redirect requests whose primary purpose is unauthorized access, credential theft, persistence, evasion, destructive action, exfiltration, or bypassing a security control. A defensive toy example, static study plan, or analysis of an owned sample is acceptable when operational scope is absent.

## Reproducibility standard

Return, unless the user requests a different format:

1. Scope, authorization assumption, exclusions, and target inventory.
2. Artifact hashes, environment, tool versions, and containment.
3. Ordered method and analysis timeline.
4. Evidence-backed findings with confidence and alternatives.
5. Impact, remediation, detection, or compatibility guidance.
6. Limitations, unanswered questions, and next experiments.
7. A safe appendix of commands, scripts, offsets, traces, captures, and output references.

Keep generated manifests, samples, logs, credentials, local paths, and private identifiers outside this public skill repository.
