"""Privacy-preserving registry for optional open-source reverse-engineering tools.

The registry deliberately separates three states:

* ``mcp_native``: implemented by the bundled read-only Python MCP server.
* ``mcp_static``: callable through a fixed, bounded static adapter.
* ``probe_only``: detected and recorded, but not invoked by the bundled server.

Dynamic, emulation, fuzzing, and host-forensics tools remain probe-only until a
separately reviewed isolated runner is configured.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
from collections.abc import Callable, Iterable
from importlib import metadata
from pathlib import Path
from typing import Any


TOOLCHAIN_REGISTRY: tuple[dict[str, Any], ...] = (
    {
        "id": "lief",
        "name": "LIEF",
        "category": "static",
        "commands": (),
        "python_modules": ("lief",),
        "adapter": "mcp_native",
        "requires_isolation": False,
    },
    {
        "id": "capstone",
        "name": "Capstone",
        "category": "static",
        "commands": (),
        "python_modules": ("capstone",),
        "adapter": "mcp_native",
        "requires_isolation": False,
    },
    {
        "id": "yara-python",
        "name": "YARA",
        "category": "malware_triage",
        "commands": ("yara",),
        "python_modules": ("yara",),
        "adapter": "mcp_native",
        "requires_isolation": False,
    },
    {
        "id": "gnu-binutils",
        "name": "GNU binutils",
        "category": "static",
        "commands": ("file", "readelf", "objdump", "nm", "strings"),
        "python_modules": (),
        "adapter": "mcp_static",
        "requires_isolation": True,
    },
    {
        "id": "llvm-tools",
        "name": "LLVM object tools",
        "category": "static",
        "commands": ("llvm-readobj", "llvm-objdump"),
        "python_modules": (),
        "adapter": "mcp_static",
        "requires_isolation": True,
    },
    {
        "id": "ghidra",
        "name": "Ghidra",
        "category": "deep_static",
        "commands": ("analyzeHeadless",),
        "python_modules": (),
        "adapter": "probe_only",
        "requires_isolation": True,
    },
    {
        "id": "rizin",
        "name": "Rizin",
        "category": "static_debug",
        "commands": ("rizin", "rz-bin"),
        "python_modules": (),
        "adapter": "probe_only",
        "requires_isolation": True,
    },
    {
        "id": "retdec",
        "name": "RetDec",
        "category": "decompilation",
        "commands": ("retdec-decompiler" ,),
        "python_modules": (),
        "adapter": "probe_only",
        "requires_isolation": True,
    },
    {
        "id": "angr",
        "name": "angr",
        "category": "program_reasoning",
        "commands": (),
        "python_modules": ("angr",),
        "adapter": "probe_only",
        "requires_isolation": True,
    },
    {
        "id": "unicorn",
        "name": "Unicorn Engine",
        "category": "emulation",
        "commands": (),
        "python_modules": ("unicorn",),
        "adapter": "probe_only",
        "requires_isolation": True,
    },
    {
        "id": "miasm",
        "name": "Miasm",
        "category": "program_reasoning",
        "commands": (),
        "python_modules": ("miasm",),
        "adapter": "probe_only",
        "requires_isolation": True,
    },
    {
        "id": "gdb-lldb",
        "name": "GDB / LLDB",
        "category": "dynamic_debugging",
        "commands": ("gdb", "gdbserver", "lldb"),
        "python_modules": (),
        "adapter": "probe_only",
        "requires_isolation": True,
    },
    {
        "id": "frida",
        "name": "Frida",
        "category": "dynamic_instrumentation",
        "commands": ("frida", "frida-trace"),
        "python_modules": ("frida",),
        "adapter": "probe_only",
        "requires_isolation": True,
    },
    {
        "id": "qemu",
        "name": "QEMU user-mode",
        "category": "emulation",
        "commands": ("qemu-aarch64", "qemu-arm", "qemu-i386", "qemu-x86_64", "qemu-mips"),
        "python_modules": (),
        "adapter": "probe_only",
        "requires_isolation": True,
    },
    {
        "id": "rr-tracing",
        "name": "rr",
        "category": "dynamic_tracing",
        "commands": ("rr",),
        "python_modules": (),
        "adapter": "probe_only",
        "requires_isolation": True,
    },
    {
        "id": "syscall-tracing",
        "name": "strace / ltrace",
        "category": "dynamic_tracing",
        "commands": ("strace", "ltrace"),
        "python_modules": (),
        "adapter": "probe_only",
        "requires_isolation": True,
    },
    {
        "id": "aflplusplus",
        "name": "AFL++",
        "category": "fuzzing",
        "commands": ("afl-fuzz", "afl-showmap"),
        "python_modules": (),
        "adapter": "probe_only",
        "requires_isolation": True,
    },
    {
        "id": "honggfuzz",
        "name": "Honggfuzz",
        "category": "fuzzing",
        "commands": ("honggfuzz",),
        "python_modules": (),
        "adapter": "probe_only",
        "requires_isolation": True,
    },
    {
        "id": "libfuzzer",
        "name": "LLVM libFuzzer",
        "category": "fuzzing",
        "commands": (),
        "python_modules": (),
        "adapter": "probe_only",
        "requires_isolation": True,
    },
    {
        "id": "capa-floss",
        "name": "capa / FLOSS",
        "category": "malware_triage",
        "commands": ("capa", "floss"),
        "python_modules": (),
        "adapter": "probe_only",
        "requires_isolation": True,
    },
    {
        "id": "volatility3",
        "name": "Volatility 3",
        "category": "memory_forensics",
        "commands": ("vol", "vol.py"),
        "python_modules": ("volatility3",),
        "adapter": "probe_only",
        "requires_isolation": True,
    },
    {
        "id": "pyelftools",
        "name": "pyelftools",
        "category": "binary_parsing",
        "commands": (),
        "python_modules": ("elftools",),
        "adapter": "probe_only",
        "requires_isolation": True,
    },
    {
        "id": "pefile",
        "name": "pefile",
        "category": "binary_parsing",
        "commands": (),
        "python_modules": ("pefile",),
        "adapter": "probe_only",
        "requires_isolation": True,
    },
    {
        "id": "protocol-analysis",
        "name": "Wireshark / Scapy / Kaitai",
        "category": "protocol_format",
        "commands": ("tshark", "wireshark", "kaitai-struct-compiler"),
        "python_modules": ("scapy", "kaitaistruct"),
        "adapter": "probe_only",
        "requires_isolation": True,
    },
    {
        "id": "android-analysis",
        "name": "JADX / Apktool",
        "category": "mobile",
        "commands": ("jadx", "apktool"),
        "python_modules": (),
        "adapter": "probe_only",
        "requires_isolation": True,
    },
    {
        "id": "dotnet-analysis",
        "name": "ILSpy",
        "category": "managed_code",
        "commands": ("ilspycmd", "ILSpy"),
        "python_modules": (),
        "adapter": "probe_only",
        "requires_isolation": True,
    },
    {
        "id": "firmware-analysis",
        "name": "Binwalk",
        "category": "firmware",
        "commands": ("binwalk",),
        "python_modules": ("binwalk",),
        "adapter": "probe_only",
        "requires_isolation": True,
    },
    {
        "id": "supply-chain",
        "name": "Syft / Grype / OSV-Scanner / Trivy / Cosign",
        "category": "supply_chain",
        "commands": ("syft", "grype", "osv-scanner", "trivy", "cosign"),
        "python_modules": (),
        "adapter": "probe_only",
        "requires_isolation": False,
    },
    {
        "id": "source-analysis",
        "name": "Semgrep / Joern",
        "category": "source_dataflow",
        "commands": ("semgrep", "joern"),
        "python_modules": (),
        "adapter": "probe_only",
        "requires_isolation": True,
    },
    {
        "id": "web-recon",
        "name": "Scrapy / Playwright / Katana",
        "category": "authorized_web_collection",
        "commands": ("scrapy", "playwright", "katana"),
        "python_modules": ("scrapy", "playwright"),
        "adapter": "probe_only",
        "requires_isolation": True,
    },
    {
        "id": "isolated-lab",
        "name": "Docker / Podman / Firejail / Bubblewrap / nsjail",
        "category": "isolation",
        "commands": ("docker", "podman", "firejail", "bwrap", "nsjail"),
        "python_modules": (),
        "adapter": "probe_only",
        "requires_isolation": False,
    },
)


def _module_available(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ModuleNotFoundError, ValueError):
        return False


def _analysis_site_packages() -> Path | None:
    """Locate an explicitly configured external venv without importing it."""
    configured = os.environ.get("APEX_ANALYSIS_PYTHON", "").strip()
    if not configured:
        return None
    executable = Path(configured).expanduser()
    if not executable.is_file():
        return None
    prefix = executable.parent.parent
    candidates = sorted(prefix.glob("lib/python*/site-packages"))
    candidates.extend((prefix / "Lib" / "site-packages",))
    return next((candidate for candidate in candidates if candidate.is_dir()), None)


def _external_module_inventory() -> set[str]:
    site_packages = _analysis_site_packages()
    if site_packages is None:
        return set()
    modules: set[str] = set()
    try:
        distributions = metadata.distributions(path=[str(site_packages)])
        for distribution in distributions:
            top_level = distribution.read_text("top_level.txt") or ""
            modules.update(line.strip() for line in top_level.splitlines() if line.strip())
            for item in distribution.files or ():
                first = Path(str(item)).parts[0]
                if first and not first.endswith((".dist-info", ".egg-info")):
                    modules.add(first.removesuffix(".py"))
    except (OSError, ValueError):
        return set()
    return modules


def _external_command_inventory() -> set[str]:
    configured = os.environ.get("APEX_ANALYSIS_PYTHON", "").strip()
    if not configured:
        return set()
    executable = Path(configured).expanduser()
    if not executable.is_file():
        return set()
    bin_dir = executable.parent
    try:
        return {
            item.name.removesuffix(".exe")
            for item in bin_dir.iterdir()
            if item.is_file() and not item.is_symlink()
        }
    except OSError:
        return set()


def probe_toolchain(
    registry: Iterable[dict[str, Any]] = TOOLCHAIN_REGISTRY,
    command_lookup: Callable[[str], Any] = shutil.which,
    module_lookup: Callable[[str], bool] = _module_available,
) -> dict[str, Any]:
    """Return capability metadata without exposing local executable paths."""
    external_modules = _external_module_inventory() if module_lookup is _module_available else set()
    external_commands = _external_command_inventory() if module_lookup is _module_available else set()
    tools: list[dict[str, Any]] = []
    for spec in registry:
        commands = {name: bool(command_lookup(name) or name in external_commands) for name in spec["commands"]}
        modules = {name: bool(module_lookup(name) or name in external_modules) for name in spec["python_modules"]}
        tools.append(
            {
                "id": spec["id"],
                "name": spec["name"],
                "category": spec["category"],
                "adapter": spec["adapter"],
                "requires_isolation": spec["requires_isolation"],
                "available": any(commands.values()) or any(modules.values()),
                "commands": commands,
                "python_modules": modules,
            }
        )
    return {
        "schema": "apex-reverse-engineering/toolchain-v1",
        "paths_redacted": True,
        "external_analysis_environment_configured": bool(external_modules or external_commands),
        "tools": tools,
    }
