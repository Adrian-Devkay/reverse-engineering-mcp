# Reverse engineering-mcp

An advanced, evidence-driven, and reproducible Codex skill for authorized analysis of binaries, applications, firmware, protocols, file formats, and suspicious samples.

## Included

- Hash-first, read-only binary triage and bounded byte analysis
- Deep static-analysis routing through Ghidra MCP
- Coordinated routing for Capstone, radare2, angr, Unicorn, GDB, Frida, QEMU, YARA, capa, FLOSS, and binwalk
- Authorization checks, evidence preservation, hypothesis testing, confidence tracking, and reproducible reporting

## Install as a Codex skill

Copy this repository into the Codex skills directory using the folder name `reverse-engineering-mcp`, then invoke it as `$reverse-engineering-mcp`.

The optional local MCP server uses the dependencies in `requirements-mcp.txt`. Configure `APEX_MCP_ALLOWED_ROOTS` with only authorized case directories. Keep interpreter paths, tool locations, project caches, samples, logs, and credentials in local configuration rather than in this repository.

## Safety

This skill is for authorized analysis only. It does not authorize execution, external network access, firmware flashing, authentication bypass, credential access, or exploit deployment. Dynamic analysis must use an isolated lab and an explicit scope.

## Privacy

This repository intentionally contains no user samples, logs, credentials, virtual environments, host-specific configuration, or machine-specific absolute paths.
