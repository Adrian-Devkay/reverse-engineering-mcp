# Backend routing and escalation

Use only installed backends that are appropriate for the target and authorized scope. Tool availability is not evidence of authorization.

## Static backends

| Backend | Best use | Escalate or corroborate with |
| --- | --- | --- |
| LIEF and `file` | Format, architecture, headers, sections, imports/exports | Readelf/objdump or a second parser |
| Capstone | Bounded raw disassembly and instruction-level checks | Ghidra or radare2 context |
| Ghidra MCP | Functions, decompilation, call graphs, xrefs, namespaces, types | Assembly and bytes; review mutation calls |
| radare2 | Fast cross-checks, analysis scripting, patch/diff inspection | Ghidra or Capstone |
| YARA | Bounded signature hypotheses | FLOSS/capa and manual evidence |
| binwalk | Firmware/container signature discovery | Offset hashes, extraction review, emulation limits |

## Reasoning and emulation

Use angr for bounded CFG/path questions and Unicorn for small, explicitly scoped emulation hypotheses. Define address/range, input constraints, timeout, and stopping condition before running. Treat solver or emulator output as a hypothesis until a concrete or independent observation corroborates it.

## Dynamic backends

GDB/gdbserver provides debugger state and breakpoints; Frida provides process instrumentation; QEMU user-mode provides architecture emulation; sandbox runners provide containment and telemetry. These are execution-capable. Require a disposable snapshot, no real credentials, disabled or simulated network, and sample-specific authorization. Do not connect to real command-and-control infrastructure.

## Malware and suspicious-code backends

Use FLOSS for decoded and stack strings, capa for capability hypotheses, and YARA for repeatable signatures. Confirm capability claims with imports, control flow, configuration, or controlled traces. Report indicators with context and avoid publishing live secrets or infrastructure details.

## Protocol and format backends

Use controlled specimens and differential tests. Scapy is useful for packet construction and parsing; boofuzz or equivalent fuzzers require a local authorized target and a defined crash-handling plan. Preserve captures, input hashes, state transitions, and parser assumptions.

## Availability and fallback

Check command/module availability before relying on a backend. If a preferred tool is missing, state the gap and use a narrower fallback. Never silently replace a missing dynamic or sandbox capability with execution on the analyst host.
