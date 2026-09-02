---
name: apex-reverse-engineering
description: "Perform authorized, evidence-driven reverse engineering of binaries, apps, firmware, protocols, malware, authentication and access-control boundaries, memory safety, cryptography, and supply-chain controls with reproducible analysis and safe vulnerability triage."
---

# Apex Reverse Engineering

Use this skill when the user asks to understand, decompile, debug, instrument, compare, emulate, or document an existing binary, application, firmware image, protocol, file format, or malware sample. It is designed for advanced work, but it does not imply permission to access or modify a target.

## Operating contract

1. Establish scope before touching the target. Confirm that the sample, device, account, network, or service is owned by the user or covered by explicit authorization. If authorization or scope is unclear, ask for it and limit the response to a high-level plan.
2. Preserve evidence. Never alter the original artifact. Record SHA-256, size, timestamps, provenance, architecture, relevant tool versions, environment assumptions, and every material command or transformation. Use isolated copies and snapshots.
3. Before substantive analysis, create a case manifest with [scripts/init_case.py](scripts/init_case.py), including a plain-language authorization statement and exclusions. Do not begin target analysis when authorization is missing or the manifest cannot be written safely.
4. Select the smallest sufficient analysis mode. Read [references/modes.md](references/modes.md) when the target type or next technique is not obvious. Read [references/evidence.md](references/evidence.md) when producing a case record or report.
5. Work from hypotheses, not guesses: intake and triage, static analysis, controlled dynamic analysis, hypothesis testing, impact assessment, and reporting. Skip stages that add no evidence, but state what was not tested.
6. Prefer read-only, offline, and reversible actions. Do not contact external infrastructure, submit credentials, alter production systems, or execute an unknown sample outside an appropriately isolated lab.
7. Separate observation from inference. For each conclusion, cite the artifact, offset/address, trace, packet, log, or experiment that supports it; label confidence and unresolved alternatives.
8. Automate repeatable work where it improves reliability. Check whether tools are installed before relying on them, keep scripts deterministic, and save machine-readable outputs alongside human-readable notes.
9. For access-control work, model the actor, tenant, resource, action, and enforcement point explicitly. Never call a behavior vertical or horizontal privilege escalation without a controlled actor-to-actor comparison and a demonstrated unauthorized security impact.
10. For fuzzing, differential testing, and timing experiments, define resource limits, a deterministic seed, a stop condition, and a crash or signal collection policy before execution. Never turn a local test into an unbounded scan or denial-of-service activity.

## MCP routing

When available, use the local read-only MCP described in [references/mcp.md](references/mcp.md) for hash-first binary triage, sections, symbols, strings, and bounded byte previews. Treat MCP results as evidence, not conclusions; corroborate important claims with a second observation or an appropriate analyzer. The MCP must fail closed unless `APEX_MCP_ALLOWED_ROOTS` is explicitly set to an authorized, dedicated case directory; keep path disclosure redacted by default.

For optional free/open-source backends, read [references/toolchain.md](references/toolchain.md) and run `scripts/probe_toolchain.py` before claiming a capability is available. The bundled server exposes a privacy-preserving inventory and a fixed, bounded static adapter for common object tools. Ghidra, Rizin, RetDec, angr, Miasm, debuggers, Frida, QEMU, fuzzers, mobile tools, and forensic tools remain external or probe-only until a reviewed adapter and isolation contract are present.

Keep capability tiers explicit. The core tier is offline, read-only static analysis,
evidence capture, and provenance checking. Web Recon and isolated execution are
optional modules with separate manifests and activation gates; loading the core
skill never activates either one. Read [references/supply-chain.md](references/supply-chain.md)
for module boundaries, dependency locks, SBOM generation, source manifests, and
detached-signature verification.

For authorized web applications and APIs, read [references/web-recon.md](references/web-recon.md), create a web manifest with `scripts/init_web_case.py`, and use `scripts/web_recon.py` only with the manifest's scope. Treat web collection as a separate network capability: GET-only, bounded, robots-aware, credential-free, and private destinations blocked by default.

For dynamic observation, emulation, malware execution, or fuzzing, read [references/isolated-lab.md](references/isolated-lab.md), run `scripts/lab_preflight.py`, and use `scripts/isolated_runner.py` only with an authorized `case.json`, a locally available image pinned by an immutable `@sha256:` digest, and explicit execution approval. Tagged images and automatic pulls are unsupported. Run `scripts/capability_report.py` to distinguish bundled readiness from external or scope-dependent capability.

## Capability matrix

Treat every applicable layer below as a high-capability backend, while keeping the analysis bounded by authorization, evidence, and target format:

- Triage and corroboration: LIEF, Capstone, YARA, GNU binutils, LLVM object tools, Rizin, `file`, ELF/PE metadata, entropy, strings, and mitigations. Mark each backend as native, fixed-static, probe-only, or unavailable from the toolchain inventory.
- Deep static analysis: Ghidra MCP or another explicitly configured backend with function recovery, decompilation, disassembly, call graphs, cross-references, namespaces, and byte-pattern search. Do not imply that the bundled MCP includes Ghidra.
- Program reasoning: angr and Unicorn for bounded CFG, path, and emulation hypotheses; never treat symbolic output as proof without corroboration.
- Dynamic observation: GDB/gdbserver, Frida, and QEMU user-mode emulation in an isolated lab with explicit execution approval; these are probe-only unless a reviewed lab runner is configured.
- Access-control and privilege boundaries: role/tenant matrices, policy and scope tracing, API/GraphQL resolver review, object-level authorization checks, background-job revalidation, and bounded differential tests for vertical and horizontal authorization failures.
- Authentication security testing: bounded, authorized test-account checks for rate limits, lockout, MFA, password reset, session/token invalidation, credential-stuffing resistance, logging, and alerting. Never perform unrestricted password spraying or brute force.
- Malware and suspicious-code triage: FLOSS, capa, YARA, controlled traces, configuration extraction, persistence and injection analysis, IOC extraction, and indicator validation. Never deploy malware or connect it to live command-and-control.
- Memory safety and fuzzing: AFL++, libFuzzer, Honggfuzz, grammar-based fuzzing, ASan/UBSan, crash deduplication, minimized test cases, and root-cause triage in a bounded local harness. Fuzzers are not enabled by merely detecting their executables.
- Patch and version diff: source, bytecode, and binary diffing; changed-function prioritization; patch-intent analysis; regression comparison; and affected-version mapping.
- Cryptography and update trust: algorithm and mode review, key lifecycle, randomness, certificate/JWT/signature verification, secure boot, rollback, update packages, SBOM, and CVE/GHSA reachability.
- Platform and isolation boundaries: Linux/Windows security primitives, mobile components and entitlements, browser extensions, containers, Kubernetes identities, sandbox policies, IPC, and local boundary validation.
- Protocol and format reasoning: differential captures, grammar/state-machine inference, parser boundary review, size/encoding checks, and safe format fuzzing.
- Concurrency, side channels, and data flow: TOCTOU/race hypotheses, bounded timing comparison, cache or error-channel analysis, source-to-sink tracking, secret exposure, and privacy impact.
- Detection engineering and intelligence: YARA, Sigma, behavioral detections, SBOM/CVE correlation, IOC confidence, threat-hunting pivots, and defensive validation.
- Firmware and multi-architecture work: binwalk when available, partition/boot-chain inspection, QEMU/Unicorn emulation, and architecture-aware static cross-checks.
- Authorized Web Recon: bounded scope discovery, robots-aware collection, HTML/resource link inventory, response metadata and hashing, redirect validation, and SRC-ready surface evidence. Never infer authorization from public reachability.
- Isolated execution: Docker/Podman fixed-profile execution with network disabled, read-only case mount, non-root user, dropped capabilities, quotas, process-group timeout, and hashed/redacted output. This is a lab boundary, not a guarantee that a sample is harmless.
- Reproducibility: hash-first case manifests, pinned tool versions, preserved commands, offsets, traces, and machine-readable evidence.
- Release integrity: exact core dependency lock, path-free CycloneDX SBOM, SHA-256 source manifest, and detached-signature verification with an independently supplied public key. These prove recorded integrity and provenance checks; they do not grant authorization or make an optional backend available.

The toolchain registry is a capability inventory, not an arbitrary command runner. A backend counts as integrated only when its adapter has fixed arguments, no-shell execution, timeout and resource limits, output redaction, tests, and a documented failure mode.

“High capability” means the relevant backend is available and used appropriately; it does not mean an unknown sample is executed automatically or that a physical device can be modified without a separate authorization and recovery plan.

## Advanced analysis expectations

- Recover behavior across compiler optimizations, stripped symbols, packing, obfuscation, asynchronous control flow, and multiple architectures when applicable.
- Correlate static structure with runtime evidence: call graphs, data-flow, memory state, system calls, IPC, file changes, network traces, and configuration.
- For protocols and formats, infer grammars and state machines from differential observations; preserve captures and distinguish confirmed fields from hypotheses.
- For vulnerability work, explain root cause, reachability, affected conditions, safe validation, impact, and remediation. Prefer a non-destructive reproducer over a weaponized exploit.
- For vertical or horizontal privilege-escalation hypotheses, trace authorization from the request boundary to the final data/action sink. Check both function-level permissions and object/tenant scoping, including serializers, downloads, GraphQL, WebSockets, workers, exports, and alternate HTTP methods. Read [references/access-control.md](references/access-control.md) for the test matrix and SRC evidence gate.
- For authentication hypotheses, test only synthetic accounts in an approved lab or explicitly approved test environment. Measure the smallest bounded attempt set needed to establish rate limiting, lockout, MFA, reset-token, session, or alerting behavior; stop when the control is characterized. Read [references/authentication-testing.md](references/authentication-testing.md).
- For malware or Trojan samples, preserve the original, hash every specimen, isolate execution, disable or simulate external networking, extract behavior and IOCs, and produce detection/containment guidance. Read [references/malware-analysis.md](references/malware-analysis.md).
- For memory-safety or parser hypotheses, use a local harness with sanitizers or an approved fuzzer, retain the smallest crashing input, deduplicate by root-cause signal, and distinguish a crash from proven exploitability. Read [references/fuzzing-and-crash-analysis.md](references/fuzzing-and-crash-analysis.md).
- For a suspected fix or affected-version range, compare the nearest safe versions or commits and corroborate binary/source changes with behavior or regression tests. Read [references/patch-and-version-diff.md](references/patch-and-version-diff.md).
- For crypto, secure boot, update, dependency, or advisory questions, trace trust decisions and key/material lifecycles, then map reachability to the deployed configuration. Read [references/crypto-update-supply-chain.md](references/crypto-update-supply-chain.md).
- For OS, mobile, browser, container, Kubernetes, or IPC boundaries, identify the principal, capability, trust boundary, and final privileged sink; validate only in an approved local lab. Read [references/platform-boundaries.md](references/platform-boundaries.md).
- For protocols and file formats, preserve authorized specimens, infer only from controlled differentials, and test parser limits in a bounded harness. Read [references/protocol-format-analysis.md](references/protocol-format-analysis.md).
- For web applications or APIs, use `init_web_case.py` and `web_recon.py` for passive inventory only. Keep authentication, active discovery, rate-limit testing, and vulnerability validation as separately authorized steps. Read [references/web-recon.md](references/web-recon.md).
- For races, TOCTOU, timing, cache, or privacy hypotheses, require repeated controlled observations and a plausible security impact; do not promote statistical noise to a finding. Read [references/concurrency-sidechannels-dataflow.md](references/concurrency-sidechannels-dataflow.md).
- For CVE/GHSA or candidate findings, produce a reachability verdict, confidence, affected conditions, defensive detection, and a report-ready evidence table. Read [references/vulnerability-triage.md](references/vulnerability-triage.md).
- For dependency, source, or release-integrity work, run `scripts/provenance_report.py check-lock`, generate the SBOM only once the lock is reviewed, and verify the source manifest and detached signature when supplied. Read [references/supply-chain.md](references/supply-chain.md).
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
- for access-control findings, the actor × tenant × resource × action matrix, the denied control case, and the exact authorization/scope predicate that failed;
- for fuzzing or crash findings, the harness contract, seed/corpus provenance, sanitizer or signal evidence, minimized input, deduplication basis, and exploitability boundary;
- for version or supply-chain findings, the exact version/commit range, changed trust decision, dependency/advisory mapping, and deployment assumptions;
- for web-recon findings, the web-case manifest, exact allowed scope, request policy, robots decision, bounded limits, redacted URL evidence, response hashes, and redirect/SSRF decisions;
- for dynamic or fuzzing findings, the lab preflight, image digest, fixed profile, isolation policy, execution approval, limits, process result, output hashes, and sanitized traces;
- for every case, the authorization manifest, tool availability record, resource limits, and privacy/redaction settings;
- for a release or toolchain claim, the exact dependency-lock status, SBOM, source-manifest verification result, signature policy/result, and unresolved optional backends;
- the toolchain registry schema and the exact adapter state for every backend used or considered;
- an appendix of reproducible commands, scripts, offsets, traces, and tool outputs where safe to share.

Use [scripts/init_case.py](scripts/init_case.py) to create the required deterministic artifact manifest before every substantive case. Do not create a case record for a target that has not passed the scope check.
