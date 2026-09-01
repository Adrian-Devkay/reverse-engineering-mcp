# Analysis modes

Choose one primary mode and add only the supporting modes needed by the evidence. The tool names below are examples, not mandatory dependencies; verify availability and licensing before use.

## Binary and native application

Start with file type, architecture, mitigations, imports/exports, strings, embedded resources, and packer or compiler clues. Use the local binary MCP for hash-first triage and Ghidra MCP for function recovery, decompilation, call graphs, XRefs, and byte-pattern search. Build a normalized function inventory and call/data-flow hypotheses with Ghidra, IDA, Binary Ninja, or radare2. Cross-check important functions with Capstone or radare2 and use angr/Unicorn only for a bounded, explicitly scoped hypothesis. Validate important paths under a debugger such as GDB, LLDB, or WinDbg, then use Frida or equivalent instrumentation only where it answers a defined question.

Pay special attention to trust boundaries, parsers, deserializers, privilege transitions, crypto/key handling, update logic, and error paths. Treat decompiler output as a hypothesis; confirm types, ownership, bounds, and control flow against assembly and runtime observations.

## Managed, mobile, and web-adjacent targets

Identify runtime and packaging first: JVM/.NET/Native, Android APK/AAB, iOS app, WebAssembly, or browser extension. Map permissions, IPC, storage, exported components, signing, native bridges, and server assumptions. Keep client-side observations separate from claims about server behavior unless the server is also in scope.

## Malware and suspicious samples

Use a quarantined, revertible lab with no real credentials and controlled or disabled network access. Perform triage, static classification, FLOSS/capa-assisted capability extraction, sandbox execution, API/system-call tracing, persistence and configuration extraction, and indicator validation. Produce behavior timelines, IOCs, detection ideas, and containment recommendations. Never connect a sample to its real command-and-control infrastructure as part of ordinary analysis.

## Vulnerability root-cause analysis

Locate the boundary where attacker-controlled data becomes unsafe, then establish reachability and preconditions. Use source, symbols, differential behavior, sanitizers, fuzzing, emulation, or targeted tracing as appropriate. Report the smallest safe reproducer, affected versions/configurations, exploitability uncertainty, and a patch or mitigation strategy. Avoid turning a finding into a portable exploit against third-party systems.

## Protocols and file formats

Collect authorized specimens and controlled input/output pairs. Normalize captures, infer framing, fields, encodings, checksums, state transitions, and error behavior. Use differential tests and grammar hypotheses; preserve the exact specimens that support each field. Mark guessed semantics until independently confirmed.

## Firmware, embedded systems, and hardware

Inventory images, partitions, boot stages, update packages, cryptographic roots, debug interfaces, and recovery paths. Use binwalk when available, strings, emulation, QEMU/Unicorn, hardware probes, or a logic analyzer only within the approved device scope. Record whether conclusions came from an image, emulation, or physical observation. Do not flash modified images without explicit authorization and a validated recovery plan.

## Anti-analysis and obfuscation

Document the mechanism and its effect before attempting to neutralize it. Work on a copy, preserve the original behavior, and prefer observation or instrumentation over destructive patching. If an analysis requires bypassing access controls, licensing, or a security boundary, stop and obtain explicit authorization and a narrowly defined purpose.
