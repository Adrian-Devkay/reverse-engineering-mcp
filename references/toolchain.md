# Free and open-source toolchain

The bundled Python MCP server is the safety and evidence layer. External tools
are optional backends, not proof that the tool is installed or safe to run.
Run `scripts/probe_toolchain.py` before relying on any backend. The probe reports
booleans only; it never returns executable paths, reads a sample, or executes a
target.

## Integration states

| State | Meaning |
| --- | --- |
| `mcp_native` | Implemented by the bundled read-only MCP server: LIEF, Capstone, and YARA. |
| `mcp_static` | Available through fixed, bounded, read-only adapters for common object tools. |
| `probe_only` | Detected and recorded, but not invoked by the bundled server. Configure a separately reviewed adapter or lab runner before use. |

## Recommended backends

| Workstream | Tools | Default boundary |
| --- | --- | --- |
| Static triage | LIEF, Capstone, GNU binutils, LLVM object tools | Read-only; hostile inputs still need process limits. |
| Deep static analysis | Ghidra, Rizin, RetDec, angr, Miasm | Dedicated case directory; no external writes. |
| Dynamic analysis | GDB/LLDB, Frida, QEMU, rr, strace/ltrace | Isolated VM or container, no network by default, explicit approval. |
| Fuzzing | AFL++, LLVM libFuzzer, Honggfuzz | Local harness only, deterministic seed, CPU/memory/time quotas. |
| Malware and memory forensics | YARA, capa, FLOSS, Volatility 3 | Offline copy or memory image; redact secrets and personal data. |
| Protocol and formats | Wireshark/TShark, Scapy, Kaitai Struct | Authorized captures and synthetic fixtures only. |
| Authorized web collection | Scrapy, Playwright, Katana, bundled `web_recon.py` | Exact scope, GET-only, robots-aware, rate/page/byte limits, no credentials. |
| Isolation and execution | Docker, Podman, Firejail, Bubblewrap, nsjail, bundled `isolated_runner.py` | Preflight first; fixed profiles, no network, read-only mount, non-root, quotas, explicit approval. |
| Mobile and managed code | JADX, Apktool, ILSpy | Analyze owned or authorized artifacts; do not bypass signing or licensing. |
| Firmware and supply chain | Binwalk, Syft, Grype, OSV-Scanner, Trivy, Cosign | Work on disposable images and verified provenance. |
| Source and data flow | Semgrep, Joern | Authorized source tree; preserve commit and dependency provenance. |

## Installation and execution policy

Do not vendor large executables or silently install packages into a case. Keep
the skill portable: record the tool ID, availability, version, and package
provenance in the case record. Use an isolated, disposable environment for
parsers, decompilers, emulators, debuggers, fuzzers, and memory-forensics tools.

If optional Python backends are installed in a separate environment, point the
privacy-preserving probe at that interpreter explicitly:

```bash
APEX_ANALYSIS_PYTHON=/path/to/analysis-venv/bin/python python scripts/probe_toolchain.py
APEX_ANALYSIS_PYTHON=/path/to/analysis-venv/bin/python python scripts/capability_report.py
```

The probe reads distribution metadata only; it does not import or execute an
optional backend, and it reports only booleans and versions-independent status.

The registry is deliberately broader than the current adapters. A backend is
not considered integrated until it has a fixed argument builder, no-shell
execution, timeout and resource limits, output redaction, capability tests, and
a documented failure mode. Never turn the registry into an arbitrary command
runner.
