# Safe operations

Before analysis, record the authorization statement and boundaries in plain language: target, permitted techniques, time window, network limits, data handling, and stop conditions.

Create the case manifest before substantive analysis. Configure `APEX_MCP_ALLOWED_ROOTS` explicitly to a dedicated authorized case directory; the local MCP must fail closed when the variable is absent. Keep `APEX_MCP_REVEAL_PATHS` unset unless full paths are needed for a local evidence record.

For web collection, create `web-case.json` with `scripts/init_web_case.py` before any request. Use `scripts/web_recon.py` only with its exact allowed-domain scope. It is GET-only, credential-free, robots-aware, rate/page/byte limited, and blocks private destinations by default. Treat `--ignore-robots`, `--allow-private-network`, and `--allow-nonstandard-port` as explicit lab-only exceptions that must be enabled in the web manifest; the collector rejects flags that are not authorized there.

Use a disposable VM or equivalent isolation for unknown code. Disable shared credentials and sensitive mounts, snapshot before execution, constrain or simulate networking, and keep a clean copy of the sample. Treat downloaded or extracted content as untrusted.

GDB/gdbserver, Frida, QEMU user-mode emulation, and sandbox runners are execution-capable even when used only for observation. Require explicit approval for the specific sample and question, record the isolation boundary, and keep networking disabled or simulated unless the scope explicitly authorizes a controlled network experiment.

For parser, LIEF, YARA, or other native-library analysis, apply an external process timeout and OS-level CPU/memory limit in addition to in-process input-size and tool timeouts. Treat library timeouts as best-effort and preserve the process-level termination evidence.

Pause for explicit confirmation before:

- executing a sample with external network access;
- flashing firmware, changing boot state, or modifying a physical device;
- interacting with production services or real user data;
- bypassing authentication, licensing, DRM, or a security control;
- generating or testing an exploit outside a local authorized lab.

If the user cannot establish authorization, provide only a defensive study plan, benign toy example, or guidance for analyzing a sample they own. Never infer authorization from access alone.
