# Safe operations

Before analysis, record the authorization statement and boundaries in plain language: target, permitted techniques, time window, network limits, data handling, and stop conditions.

Use a disposable VM or equivalent isolation for unknown code. Disable shared credentials and sensitive mounts, snapshot before execution, constrain or simulate networking, and keep a clean copy of the sample. Treat downloaded or extracted content as untrusted.

GDB/gdbserver, Frida, QEMU user-mode emulation, and sandbox runners are execution-capable even when used only for observation. Require explicit approval for the specific sample and question, record the isolation boundary, and keep networking disabled or simulated unless the scope explicitly authorizes a controlled network experiment.

Pause for explicit confirmation before:

- executing a sample with external network access;
- flashing firmware, changing boot state, or modifying a physical device;
- interacting with production services or real user data;
- bypassing authentication, licensing, DRM, or a security control;
- generating or testing an exploit outside a local authorized lab.

If the user cannot establish authorization, provide only a defensive study plan, benign toy example, or guidance for analyzing a sample they own. Never infer authorization from access alone.
