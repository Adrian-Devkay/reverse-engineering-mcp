#!/usr/bin/env python3
"""Read-only local MCP server for evidence-first binary triage."""

from __future__ import annotations

import hashlib
import logging
import multiprocessing
import os
import re
import signal
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import capstone
import lief
import yara
from mcp.server.fastmcp import FastMCP

from toolchain_registry import probe_toolchain


LOG = logging.getLogger("apex-reverse-engineering.mcp")
MAX_PREVIEW_BYTES = 4096
MAX_BINARY_PARSE_BYTES = 64 * 1024 * 1024
MAX_HASH_BYTES = 1024 * 1024 * 1024
MAX_STRING_SCAN_BYTES = 128 * 1024 * 1024
MAX_YARA_SCAN_BYTES = 64 * 1024 * 1024
MAX_STATIC_TOOL_BYTES = 64 * 1024 * 1024
MAX_STATIC_TOOL_OUTPUT_CHARS = 1_000_000
PARSE_TIMEOUT_SECONDS = 15
DEFAULT_ROOTS: tuple[Path, ...] = ()

mcp = FastMCP("Apex Reverse Engineering - Read Only Binary Triage")


def _allowed_roots() -> tuple[Path, ...]:
    raw = os.environ.get("APEX_MCP_ALLOWED_ROOTS", "")
    roots = tuple(Path(item).expanduser().resolve() for item in raw.split(os.pathsep) if item)
    return roots or DEFAULT_ROOTS


def _display_path(path: Path) -> str:
    """Redact local directory structure unless explicitly requested for a local case."""
    if os.environ.get("APEX_MCP_REVEAL_PATHS") == "1":
        return str(path)
    return path.name


def _safe_path(path: str) -> Path:
    try:
        candidate = Path(path).expanduser().resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        raise ValueError("target path could not be resolved") from None
    if not candidate.is_file():
        raise ValueError("target is not a regular file")
    roots = _allowed_roots()
    if not roots:
        raise PermissionError("APEX_MCP_ALLOWED_ROOTS must be configured")
    if not any(candidate == root or root in candidate.parents for root in roots):
        raise PermissionError("target is outside the configured allowlist")
    return candidate


def _ensure_size(path: Path, limit: int, operation: str) -> int:
    try:
        size = path.stat().st_size
    except OSError:
        raise ValueError(f"{operation} could not stat the target") from None
    if size > limit:
        raise ValueError(f"{operation} refused: input exceeds the configured size limit")
    return size


def _redact_tool_output(value: bytes, path: Path) -> tuple[str, bool]:
    text = value.decode("utf-8", errors="replace")
    for local_value in (str(path), str(path.parent), os.environ.get("HOME", "")):
        if local_value:
            text = text.replace(local_value, "<redacted-path>")
    if len(text) > MAX_STATIC_TOOL_OUTPUT_CHARS:
        return text[:MAX_STATIC_TOOL_OUTPUT_CHARS], True
    return text, False


def _child_limits(timeout_seconds: int):
    """Return POSIX limits for a fixed static analyzer, when supported."""
    if os.name != "posix":
        return None

    def limit_resources() -> None:
        try:
            import resource

            resource.setrlimit(resource.RLIMIT_CPU, (timeout_seconds, timeout_seconds + 1))
            resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
            resource.setrlimit(resource.RLIMIT_FSIZE, (8 * 1024 * 1024, 8 * 1024 * 1024))
        except (ImportError, OSError, ValueError):
            LOG.warning("could not apply child resource limits")

    return limit_resources


def _static_tool_argv(tool_id: str, path: Path) -> list[str]:
    """Build arguments only for reviewed, read-only static commands."""
    builders = {
        "file": lambda: ["file", "--brief", "--preserve-date", "--", str(path)],
        "readelf": lambda: ["readelf", "-W", "-h", "-S", "-l", "-s", "--", str(path)],
        "objdump": lambda: ["objdump", "-x", "-d", "--", str(path)],
        "nm": lambda: ["nm", "-a", "-C", "--", str(path)],
        "strings": lambda: ["strings", "-a", "-n", "4", "--", str(path)],
        "llvm-readobj": lambda: [
            "llvm-readobj",
            "--file-headers",
            "--sections",
            "--program-headers",
            "--symbols",
            "--",
            str(path),
        ],
        "llvm-objdump": lambda: ["llvm-objdump", "-p", "-d", "--", str(path)],
    }
    try:
        return builders[tool_id]()
    except KeyError:
        raise ValueError("static tool is not in the fixed adapter allowlist") from None


def _run_fixed_static_tool(tool_id: str, path: Path, timeout_seconds: int, output_chars: int) -> dict[str, Any]:
    argv = _static_tool_argv(tool_id, path)
    if not shutil.which(argv[0]):
        raise ValueError("requested static tool is unavailable")

    with tempfile.TemporaryDirectory(prefix="apex-static-tool-") as temp_dir:
        temp_root = Path(temp_dir)
        stdout_path = temp_root / "stdout"
        stderr_path = temp_root / "stderr"
        environment = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": temp_dir,
            "TMPDIR": temp_dir,
            "XDG_CONFIG_HOME": temp_dir,
            "XDG_CACHE_HOME": temp_dir,
            "XDG_DATA_HOME": temp_dir,
            "LC_ALL": "C",
            "LANG": "C",
            "TERM": "dumb",
            "PYTHONNOUSERSITE": "1",
        }
        timed_out = False
        with stdout_path.open("wb") as stdout_handle, stderr_path.open("wb") as stderr_handle:
            process = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=stdout_handle,
                stderr=stderr_handle,
                cwd=temp_dir,
                env=environment,
                shell=False,
                start_new_session=True,
                preexec_fn=_child_limits(timeout_seconds),
            )
            try:
                process.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                if os.name == "posix":
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                else:
                    process.kill()
                process.wait()

        stdout_bytes = stdout_path.read_bytes()
        stderr_bytes = stderr_path.read_bytes()
        stdout_text, stdout_truncated = _redact_tool_output(stdout_bytes[:output_chars], path)
        stderr_text, stderr_truncated = _redact_tool_output(stderr_bytes[:output_chars], path)
        return {
            "tool": tool_id,
            "mode": "static",
            "path": _display_path(path),
            "returncode": process.returncode,
            "timed_out": timed_out,
            "stdout": stdout_text,
            "stderr": stderr_text,
            "truncated": stdout_truncated or stderr_truncated or len(stdout_bytes) > output_chars or len(stderr_bytes) > output_chars,
            "read_only_adapter": True,
        }


def _enum_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    name = getattr(value, "name", None)
    if name:
        return name
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _attr(obj: Any, name: str, default: Any = None) -> Any:
    try:
        value = getattr(obj, name)
        if isinstance(value, (list, tuple, dict)):
            return value
        if isinstance(value, (str, int, float, bool, bytes)) or getattr(value, "name", None):
            return _enum_value(value)
        return value
    except (AttributeError, RuntimeError, TypeError, ValueError):
        return default


def _plain(value: Any) -> Any:
    """Convert native-parser values into bounded, process-safe primitives."""
    if isinstance(value, bytes):
        return value.hex()
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    name = getattr(value, "name", None)
    if name:
        return str(name)
    return str(value)


def _parse_worker(path: str, channel: Any) -> None:
    """Parse in a short-lived child so native parser faults cannot kill MCP."""
    limiter = _child_limits(PARSE_TIMEOUT_SECONDS)
    if limiter is not None:
        limiter()
    try:
        binary = lief.parse(path)
        if binary is None:
            raise ValueError("unrecognized binary")
        header = _attr(binary, "header", {})
        sections = []
        for section in _attr(binary, "sections", []) or []:
            sections.append(
                {
                    "name": _plain(_attr(section, "name")),
                    "offset": _plain(_attr(section, "offset")),
                    "size": _plain(_attr(section, "size")),
                    "virtual_address": _plain(_attr(section, "virtual_address")),
                    "virtual_size": _plain(_attr(section, "virtual_size")),
                    "entropy": _plain(_attr(section, "entropy")),
                    "permissions": _plain(_attr(section, "permissions")),
                }
            )
        imports = []
        for library in _attr(binary, "imports", []) or []:
            entries = []
            for entry in _attr(library, "entries", []) or []:
                entries.append(
                    {
                        "name": _plain(_attr(entry, "name")),
                        "ordinal": _plain(_attr(entry, "ordinal")),
                    }
                )
            imports.append({"name": _plain(_attr(library, "name")), "entries": entries})
        exports = []
        for item in _attr(binary, "exported_functions", []) or []:
            exports.append(
                {
                    "name": _plain(_attr(item, "name")),
                    "address": _plain(_attr(item, "address")),
                    "ordinal": _plain(_attr(item, "ordinal")),
                }
            )
        channel.send(
            {
                "ok": True,
                "binary": {
                    "format": _plain(_attr(binary, "format")),
                    "header": {
                        "machine_type": _plain(_attr(header, "machine_type")),
                        "machine": _plain(_attr(header, "machine")),
                    },
                    "entrypoint": _plain(_attr(binary, "entrypoint")),
                    "imagebase": _plain(_attr(binary, "imagebase")),
                    "sections": sections,
                    "imports": imports,
                    "exports": exports,
                    "has_nx": _plain(_attr(binary, "has_nx")),
                    "has_pie": _plain(_attr(binary, "is_pie")),
                    "has_canary": _plain(_attr(binary, "has_stack_canary")),
                },
            }
        )
    except Exception as exc:  # Native parser errors stay inside the worker.
        try:
            channel.send({"ok": False, "error": type(exc).__name__})
        except (BrokenPipeError, EOFError, OSError):
            pass
    finally:
        channel.close()


def _parse(path: Path) -> dict[str, Any]:
    _ensure_size(path, MAX_BINARY_PARSE_BYTES, "binary parse")
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe(duplex=False)
    process = context.Process(target=_parse_worker, args=(str(path), child), daemon=True)
    try:
        process.start()
        child.close()
        payload = parent.recv() if parent.poll(PARSE_TIMEOUT_SECONDS) else None
    except (EOFError, OSError, RuntimeError) as exc:
        LOG.warning("LIEF worker failed for %s: %s", path.name, type(exc).__name__)
        payload = None
    finally:
        if process.is_alive():
            process.terminate()
        process.join(timeout=2)
        if process.is_alive():
            process.kill()
            process.join(timeout=1)
        parent.close()
        try:
            child.close()
        except OSError:
            pass
    if not isinstance(payload, dict) or payload.get("ok") is not True or not isinstance(payload.get("binary"), dict):
        LOG.warning("LIEF parse failed for %s", path.name)
        raise ValueError(f"invalid or unsupported binary: {path.name}") from None
    return payload["binary"]


def _hash(path: Path) -> dict[str, Any]:
    _ensure_size(path, MAX_HASH_BYTES, "hash")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    info = path.stat()
    return {"path": _display_path(path), "size_bytes": info.st_size, "sha256": digest.hexdigest()}


def _strings(data: bytes, min_length: int) -> list[dict[str, Any]]:
    pattern = re.compile(rb"[ -~]{%d,}" % min_length)
    found: list[dict[str, Any]] = []
    for match in pattern.finditer(data):
        found.append({"offset": match.start(), "encoding": "ascii", "value": match.group().decode("ascii")})

    wide = re.compile((rb"(?:[ -~]\x00){%d,}") % min_length)
    for match in wide.finditer(data):
        raw = match.group()[::2]
        found.append({"offset": match.start(), "encoding": "utf-16le", "value": raw.decode("ascii")})
    return sorted(found, key=lambda item: item["offset"])


def _read_range(path: Path, offset: int, length: int) -> bytes:
    if offset < 0 or length < 1 or length > MAX_PREVIEW_BYTES:
        raise ValueError(f"offset must be non-negative and length must be 1..{MAX_PREVIEW_BYTES}")
    with path.open("rb") as handle:
        handle.seek(offset)
        return handle.read(length)


@mcp.tool()
def apex_hash_file(path: str) -> dict[str, Any]:
    """Return the SHA-256, size, and redacted path without modifying the file."""
    return _hash(_safe_path(path))


@mcp.tool()
def apex_binary_overview(path: str) -> dict[str, Any]:
    """Return parsed format, architecture, entry point, and binary-level counts."""
    safe = _safe_path(path)
    binary = _parse(safe)
    header = binary["header"]
    sections = binary["sections"]
    imports = binary["imports"]
    exports = binary["exports"]
    result = _hash(safe)
    result.update(
        {
            "format": binary["format"],
            "architecture": header.get("machine_type") or header.get("machine"),
            "entrypoint": binary["entrypoint"],
            "imagebase": binary["imagebase"],
            "section_count": len(sections),
            "import_library_count": len(imports),
            "export_count": len(exports),
            "has_nx": binary["has_nx"],
            "has_pie": binary["has_pie"],
            "has_canary": binary["has_canary"],
        }
    )
    return result


@mcp.tool()
def apex_sections(path: str, limit: int = 500) -> list[dict[str, Any]]:
    """List parsed sections with names, ranges, permissions, and entropy when available."""
    safe = _safe_path(path)
    if not 1 <= limit <= 5000:
        raise ValueError("limit must be between 1 and 5000")
    binary = _parse(safe)
    result: list[dict[str, Any]] = []
    for index, section in enumerate(binary["sections"]):
        if index >= limit:
            break
        result.append(
            {
                "name": section["name"],
                "offset": section["offset"],
                "size": section["size"],
                "virtual_address": section["virtual_address"],
                "virtual_size": section["virtual_size"],
                "entropy": section["entropy"],
                "permissions": section["permissions"],
            }
        )
    return result


@mcp.tool()
def apex_symbols(path: str, limit: int = 500) -> dict[str, Any]:
    """List imported libraries/functions and exported functions without executing the binary."""
    safe = _safe_path(path)
    if not 1 <= limit <= 5000:
        raise ValueError("limit must be between 1 and 5000")
    binary = _parse(safe)
    imports: list[dict[str, Any]] = []
    for library_index, library in enumerate(binary["imports"]):
        if library_index >= limit:
            break
        entries = []
        for entry_index, entry in enumerate(library["entries"]):
            if entry_index >= limit:
                break
            entries.append({"name": entry["name"], "ordinal": entry["ordinal"]})
        imports.append({"library": library["name"], "entries": entries})
    exports = []
    for export_index, item in enumerate(binary["exports"]):
        if export_index >= limit:
            break
        exports.append({"name": item["name"], "address": item["address"], "ordinal": item["ordinal"]})
    return {"path": _display_path(safe), "imports": imports, "exports": exports}


@mcp.tool()
def apex_extract_strings(path: str, min_length: int = 4, limit: int = 1000) -> dict[str, Any]:
    """Extract ASCII and UTF-16LE strings from a bounded byte scan; never runs the sample."""
    safe = _safe_path(path)
    if not 3 <= min_length <= 128:
        raise ValueError("min_length must be between 3 and 128")
    if not 1 <= limit <= 10000:
        raise ValueError("limit must be between 1 and 10000")
    if safe.stat().st_size > MAX_STRING_SCAN_BYTES:
        raise ValueError(f"refusing string scan above {MAX_STRING_SCAN_BYTES} bytes")
    data = safe.read_bytes()
    values = _strings(data, min_length)[:limit]
    return {"path": _display_path(safe), "scanned_bytes": len(data), "strings": values, "truncated": len(values) >= limit}


@mcp.tool()
def apex_read_bytes(path: str, offset: int = 0, length: int = 256) -> dict[str, Any]:
    """Return a bounded hex preview from a file for evidence-backed byte inspection."""
    safe = _safe_path(path)
    data = _read_range(safe, offset, length)
    return {"path": _display_path(safe), "offset": offset, "length": len(data), "hex": data.hex(), "eof": len(data) < length}


@mcp.tool()
def apex_disassemble(
    path: str,
    offset: int = 0,
    length: int = 256,
    architecture: str = "x86",
    mode: str = "64",
) -> dict[str, Any]:
    """Disassemble a bounded raw byte range with Capstone without executing it."""
    safe = _safe_path(path)
    if length > MAX_PREVIEW_BYTES:
        raise ValueError(f"length must be <= {MAX_PREVIEW_BYTES}")
    arch_modes = {
        ("x86", "16"): (capstone.CS_ARCH_X86, capstone.CS_MODE_16),
        ("x86", "32"): (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
        ("x86", "64"): (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
        ("arm", "32"): (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
        ("thumb", "32"): (capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB),
        ("arm64", "64"): (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
        ("mips", "32"): (capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32),
        ("mips", "64"): (capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS64),
    }
    key = (architecture.lower(), mode)
    if key not in arch_modes:
        raise ValueError(f"unsupported architecture/mode: {architecture}/{mode}")
    data = _read_range(safe, offset, length)
    disassembler = capstone.Cs(*arch_modes[key])
    disassembler.detail = False
    instructions = [
        {"address": ins.address, "mnemonic": ins.mnemonic, "operands": ins.op_str, "bytes": ins.bytes.hex()}
        for ins in disassembler.disasm(data, offset)
    ]
    return {"path": _display_path(safe), "offset": offset, "scanned_bytes": len(data), "architecture": architecture, "mode": mode, "instructions": instructions}


@mcp.tool()
def apex_entropy(path: str, offset: int = 0, length: int = 65536) -> dict[str, Any]:
    """Calculate Shannon entropy for a bounded byte range without executing the file."""
    safe = _safe_path(path)
    if offset < 0 or length < 1 or length > 1024 * 1024:
        raise ValueError("offset must be non-negative and length must be 1..1048576")
    with safe.open("rb") as handle:
        handle.seek(offset)
        data = handle.read(length)
    if not data:
        return {"path": _display_path(safe), "offset": offset, "scanned_bytes": 0, "entropy": 0.0}
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    entropy = -sum((count / total) * __import__("math").log2(count / total) for count in counts if count)
    return {"path": _display_path(safe), "offset": offset, "scanned_bytes": total, "entropy": round(entropy, 6), "max_entropy": 8.0}


@mcp.tool()
def apex_yara_scan(path: str, rules_text: str, timeout_seconds: int = 10) -> dict[str, Any]:
    """Scan an authorized file with inline YARA rules; rules cannot include external files."""
    safe = _safe_path(path)
    _ensure_size(safe, MAX_YARA_SCAN_BYTES, "YARA scan")
    if not rules_text.strip() or len(rules_text) > 100_000:
        raise ValueError("rules_text must be non-empty and <= 100000 characters")
    if not 1 <= timeout_seconds <= 60:
        raise ValueError("timeout_seconds must be between 1 and 60")
    try:
        rules = yara.compile(source=rules_text, includes=False)
        matches = rules.match(str(safe), timeout=timeout_seconds)
    except Exception as exc:
        LOG.warning("YARA scan failed for %s: %s", safe.name, type(exc).__name__)
        raise ValueError("YARA scan failed") from None
    return {"path": _display_path(safe), "matches": [{"rule": match.rule, "namespace": match.namespace, "tags": list(match.tags)} for match in matches]}


@mcp.tool()
def apex_static_tool(
    path: str,
    tool_id: str,
    timeout_seconds: int = 10,
    output_chars: int = 100_000,
) -> dict[str, Any]:
    """Run one fixed, bounded, read-only static adapter; never accepts arbitrary commands."""
    safe = _safe_path(path)
    _ensure_size(safe, MAX_STATIC_TOOL_BYTES, "static tool")
    if not 1 <= timeout_seconds <= 30:
        raise ValueError("timeout_seconds must be between 1 and 30")
    if not 1_000 <= output_chars <= MAX_STATIC_TOOL_OUTPUT_CHARS:
        raise ValueError(f"output_chars must be between 1000 and {MAX_STATIC_TOOL_OUTPUT_CHARS}")
    return _run_fixed_static_tool(tool_id, safe, timeout_seconds, output_chars)


@mcp.tool()
def apex_toolchain_inventory() -> dict[str, Any]:
    """Report optional open-source backends and their integration/isolation state."""
    return probe_toolchain()


@mcp.tool()
def apex_toolchain_status() -> dict[str, Any]:
    """Report available local reverse-engineering backends without running an analyzed sample."""
    inventory = probe_toolchain()
    commands = {
        name: available
        for tool in inventory["tools"]
        for name, available in tool["commands"].items()
    }
    return {
        "mcp": "available",
        "python_modules": {
            "lief": getattr(lief, "__version__", "available"),
            "capstone": getattr(capstone, "__version__", "available"),
            "yara": getattr(yara, "__version__", "available"),
        },
        "commands": commands,
        "toolchain": inventory["tools"],
        "paths_redacted": True,
        "read_only_server": True,
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    mcp.run(transport="stdio")
