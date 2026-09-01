# Reverse engineering-mcp

![Validation](actions/workflows/validate.yml/badge.svg)

An advanced, evidence-driven, reproducible Codex skill for authorized reverse engineering of binaries, applications, firmware, protocols, file formats, and suspicious samples.

## Why this exists

Reverse engineering quality depends on more than a decompiler. This skill provides a disciplined investigation loop that preserves artifact integrity, routes questions to appropriate static or dynamic backends, separates observations from hypotheses, and produces a report another analyst can reproduce.

## Capabilities

| Area | Coverage |
| --- | --- |
| Binary triage | Hashes, LIEF metadata, sections, symbols, imports/exports, strings, entropy, mitigations |
| Deep static analysis | Ghidra MCP, function recovery, decompilation, disassembly, call graphs, xrefs, namespaces, byte search |
| Program reasoning | angr and Unicorn for bounded CFG, path, and emulation hypotheses |
| Dynamic observation | GDB/gdbserver, Frida, QEMU user-mode emulation, isolated sandbox workflows |
| Malware triage | YARA, capa, FLOSS, configuration and indicator extraction, controlled behavior timelines |
| Firmware and formats | binwalk, partition and boot-chain inspection, multi-architecture analysis, differential specimens |
| Evidence | Hash-first case manifests, confidence labels, evidence tables, reproducibility appendices |

## Investigation model

```text
scope gate
    -> integrity and intake
    -> bounded triage
    -> static reconstruction
    -> hypothesis test
    -> controlled dynamic observation
    -> independent correlation
    -> findings and remediation report
```

The skill escalates only when the current evidence cannot answer the question. Dynamic execution, network access, hardware changes, and exploit validation remain explicitly gated.

## Install

Copy the repository into the Codex skills directory under the folder name `reverse-engineering-mcp`, then invoke it as `$reverse-engineering-mcp`.

The optional read-only MCP server can be installed in an isolated environment:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-mcp.txt
python mcp_server.py
```

For extended analysis, install the backends listed in `requirements-analysis.txt` and expose their executables through a local `PATH`. Ghidra MCP is an optional separate backend; keep its project cache outside the sample directory and set `APEX_GHIDRA_PROJECT_DIR` locally.

## MCP configuration

Use absolute paths in local configuration, not in this repository. The essential safety setting is an allowlist containing only authorized case directories:

```toml
[mcp_servers.reverse_engineering_binary]
command = "/absolute/path/to/skill/.venv/bin/python"
args = ["/absolute/path/to/skill/mcp_server.py"]

[mcp_servers.reverse_engineering_binary.env]
APEX_MCP_ALLOWED_ROOTS = "/tmp:/absolute/path/to/authorized-case"
```

The local server is read-only with respect to analyzed artifacts. It hashes, parses, scans, and reads bounded ranges; it does not execute samples, make network connections, or modify the input file.

## Documentation map

- [`SKILL.md`](SKILL.md): core decision contract and routing rules
- [`references/workflow.md`](references/workflow.md): phase-by-phase investigation checklist
- [`references/modes.md`](references/modes.md): target-specific playbooks
- [`references/tool-routing.md`](references/tool-routing.md): backend selection and escalation criteria
- [`references/evidence.md`](references/evidence.md): evidence quality and report requirements
- [`references/case-schema.md`](references/case-schema.md): machine-readable case record
- [`references/report-template.md`](references/report-template.md): analyst-ready report structure
- [`references/mcp.md`](references/mcp.md): local MCP integration and configuration boundaries
- [`scripts/init_case.py`](scripts/init_case.py): deterministic hash-first manifest generator

## Safety and responsible use

Use only on artifacts, devices, services, and data you own or are explicitly authorized to assess. Do not contact real command-and-control infrastructure, submit credentials, bypass authentication or licensing, flash firmware, or deploy exploits. Use a disposable lab for unknown code and record the isolation boundary.

## Privacy promise

This repository contains only generic skill instructions, source code, documentation, tests, and dependency declarations. It intentionally excludes user samples, logs, credentials, virtual environments, host-specific configuration, private identifiers, and machine-specific absolute paths. Generated case records belong in ignored local directories and must not be committed.

## Development

Run the local checks before opening a pull request:

```bash
python3 -m pip install -r requirements-mcp.txt -r requirements-dev.txt
python3 -m pytest -q
python3 -m py_compile mcp_server.py scripts/init_case.py
```

## License

MIT. See [`LICENSE`](LICENSE).
