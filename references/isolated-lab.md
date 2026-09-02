# Isolated lab execution

Dynamic observation, emulation, debugging, malware execution, and fuzzing are
not enabled by tool discovery alone. Run `scripts/lab_preflight.py` first, then
use `scripts/isolated_runner.py` only for an existing authorized `case.json`.
Use `scripts/capability_report.py` to record which backend and isolation
contracts are actually ready on the current host.

The runner has fixed profiles (`native`, `strace`, `gdb-batch`, and selected
QEMU user-mode profiles). It requires `--execution-approved`, a local Docker or
Podman image referenced by an immutable `@sha256:` digest, and uses:

- `--network=none` and no automatic image pulls;
- a read-only case mount and disposable tmpfs directories;
- a non-root numeric user, dropped capabilities, and no-new-privileges;
- CPU, memory, PID, file-size, output, and wall-clock limits;
- no shell, no host credentials, no cookies, and no inherited user config;
- report hashes by default, with output inclusion opt-in and redacted.

Tagged image references are rejected. There is no convenience override: resolve
and verify the image digest in the controlled lab before running the runner.

The container is a boundary for authorized local analysis, not a guarantee that
an unknown sample is harmless. Prefer a disposable VM for malware, kernel,
escape, hardware, or hostile multi-process analysis. Never add arbitrary command
execution, external networking, persistence, credential access, or exploit
delivery to the runner.
