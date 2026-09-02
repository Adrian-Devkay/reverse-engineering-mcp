# Analysis modes

Choose one primary mode and add only the supporting modes needed by the evidence. The tool names below are examples, not mandatory dependencies; verify availability and licensing before use.

## Binary and native application

Start with file type, architecture, mitigations, imports/exports, strings, embedded resources, and packer or compiler clues. Use the local binary MCP for hash-first triage and Ghidra MCP for function recovery, decompilation, call graphs, XRefs, and byte-pattern search. Build a normalized function inventory and call/data-flow hypotheses with Ghidra, IDA, Binary Ninja, or radare2. Cross-check important functions with Capstone or radare2 and use angr/Unicorn only for a bounded, explicitly scoped hypothesis. Validate important paths under a debugger such as GDB, LLDB, or WinDbg, then use Frida or equivalent instrumentation only where it answers a defined question.

Pay special attention to trust boundaries, parsers, deserializers, privilege transitions, crypto/key handling, update logic, and error paths. Treat decompiler output as a hypothesis; confirm types, ownership, bounds, and control flow against assembly and runtime observations.

## Managed, mobile, and web-adjacent targets

Identify runtime and packaging first: JVM/.NET/Native, Android APK/AAB, iOS app, WebAssembly, or browser extension. Map permissions, IPC, storage, exported components, signing, native bridges, and server assumptions. Keep client-side observations separate from claims about server behavior unless the server is also in scope.

## Authorized web applications and APIs

Create a web case with an explicit authorization basis and exact hostname scope. Use the bounded collector for passive surface inventory: HTML and resource links, response metadata, redirects, robots policy, and response hashes. Keep credentials, cookies, query values, and page bodies out of the report. Do not submit forms, execute JavaScript, brute-force paths, test rate limits, or validate vulnerabilities until those actions are separately authorized and isolated.

Read [web-recon.md](web-recon.md) for the manifest, network gates, SSRF protections, and evidence format.

## Malware and suspicious samples

Use a quarantined, revertible lab with no real credentials and controlled or disabled network access. Perform triage, static classification, FLOSS/capa-assisted capability extraction, sandbox execution, API/system-call tracing, persistence and configuration extraction, and indicator validation. Produce behavior timelines, IOCs, detection ideas, and containment recommendations. Never connect a sample to its real command-and-control infrastructure as part of ordinary analysis.

Read [malware-analysis.md](malware-analysis.md) for the evidence record, containment rules, and safe dynamic-analysis checklist.

## Authentication and credential-control testing

Use this mode for an owned application or explicitly authorized test environment when the question concerns login defenses, password policy, MFA, session handling, reset flows, credential stuffing, rate limiting, lockout, or detection. Use synthetic accounts and a bounded differential test; do not run unrestricted password spraying, use third-party credential lists, or test real user credentials.

Read [authentication-testing.md](authentication-testing.md) for the test matrix, stopping conditions, and SRC-quality evidence requirements.

## Vulnerability root-cause analysis

Locate the boundary where attacker-controlled data becomes unsafe, then establish reachability and preconditions. Use source, symbols, differential behavior, sanitizers, fuzzing, emulation, or targeted tracing as appropriate. Report the smallest safe reproducer, affected versions/configurations, exploitability uncertainty, and a patch or mitigation strategy. Avoid turning a finding into a portable exploit against third-party systems.

Read [fuzzing-and-crash-analysis.md](fuzzing-and-crash-analysis.md) for memory-safety and parser crashes, [patch-and-version-diff.md](patch-and-version-diff.md) for fix and affected-version analysis, and [vulnerability-triage.md](vulnerability-triage.md) for CVE/GHSA reachability and report disposition.

## Protocols and file formats

Collect authorized specimens and controlled input/output pairs. Normalize captures, infer framing, fields, encodings, checksums, state transitions, and error behavior. Use differential tests and grammar hypotheses; preserve the exact specimens that support each field. Mark guessed semantics until independently confirmed.

Read [protocol-format-analysis.md](protocol-format-analysis.md) for grammar inference, differential captures, and bounded parser testing.

## Firmware, embedded systems, and hardware

Inventory images, partitions, boot stages, update packages, cryptographic roots, debug interfaces, and recovery paths. Use binwalk when available, strings, emulation, QEMU/Unicorn, hardware probes, or a logic analyzer only within the approved device scope. Record whether conclusions came from an image, emulation, or physical observation. Do not flash modified images without explicit authorization and a validated recovery plan.

Read [crypto-update-supply-chain.md](crypto-update-supply-chain.md) for update trust, secure boot, rollback, signatures, SBOM, and dependency reachability.

## Cryptography, supply chain, and trust decisions

Review cryptographic use, key lifecycle, certificate or token verification, update packages, secure boot, rollback, dependency provenance, SBOM, and advisory reachability. Treat algorithm names or a dependency version alone as leads; establish the actual trust decision and deployment path.

Read [crypto-update-supply-chain.md](crypto-update-supply-chain.md) for the trust-chain checklist.

## Platform and isolation boundaries

Map principals, capabilities, IPC, exported components, sandbox policies, OS security primitives, container identities, Kubernetes RBAC, browser extension permissions, and mobile entitlements. Validate only in an authorized lab and stop before broad escape or persistence testing.

Read [platform-boundaries.md](platform-boundaries.md) for platform-specific boundaries.

## Concurrency, side channels, and data flow

Use controlled, repeated local observations for races, TOCTOU, timing, cache, error-channel, secret-flow, and privacy hypotheses. Require a stable signal and a meaningful boundary impact before reporting.

Read [concurrency-sidechannels-dataflow.md](concurrency-sidechannels-dataflow.md) for the evidence standard.

## Anti-analysis and obfuscation

Document the mechanism and its effect before attempting to neutralize it. Work on a copy, preserve the original behavior, and prefer observation or instrumentation over destructive patching. If an analysis requires bypassing access controls, licensing, or a security boundary, stop and obtain explicit authorization and a narrowly defined purpose.
