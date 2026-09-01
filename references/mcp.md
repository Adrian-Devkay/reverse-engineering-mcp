# Local MCP integration

The skill has an optional local stdio MCP server at `mcp_server.py`. It uses the official MCP Python SDK and LIEF, both installed into the skill's private virtual environment. The server is read-only: it hashes and parses files, extracts strings, and reads bounded byte ranges; it never executes a sample, makes network connections, or writes to an analyzed artifact.

For deep static analysis, the skill can connect to a local Ghidra MCP backend. It adds function recovery, decompilation, disassembly, call graphs, cross-references, namespace and symbol navigation, and byte-pattern search. Keep its project cache separate from the input artifact, configure it with `APEX_GHIDRA_PROJECT_DIR`, and disable project resets by default.

The analysis toolchain can add Capstone, radare2, angr, Unicorn, Frida, YARA, capa, FLOSS, GDB/gdbserver, QEMU user-mode binaries, and binwalk. Provide them through the configured `PATH` or an isolated virtual environment; dynamic tools remain approval- and isolation-gated. Report optional backends as unavailable when their executable or module is absent.

The Codex configuration should launch the server with an absolute interpreter path and an explicit `APEX_MCP_ALLOWED_ROOTS` allowlist. Add only directories that contain authorized samples. Prefer `/tmp` or a dedicated case directory over a broad home-directory root. Keep machine-specific paths in local configuration, never in this repository.

Use the binary MCP for deterministic triage and the Ghidra MCP for deep static analysis. Use the shell or a dedicated analyzer only when the MCP surface cannot answer the hypothesis. The stack still does not replace a debugger or a sandbox; those remain separately authorized backends.

If a file is outside the allowlist, expand the allowlist only after confirming scope. Do not weaken the read-only design to add execution, live debugging, firmware flashing, external network access, or arbitrary shell commands without a separate review and explicit authorization.
