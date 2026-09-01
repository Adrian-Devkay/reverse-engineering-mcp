#!/usr/bin/env python3
"""Read-only local MCP server for evidence-first binary triage."""

from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
from pathlib import Path
from typing import Any

import capstone
import lief
import yara
from mcp.server.fastmcp import FastMCP


LOG = logging.getLogger("apex-reverse-engineering.mcp")
MAX_PREVIEW_BYTES = 4096
MAX_STRING_SCAN_BYTES = 128 * 1024 * 1024
DEFAULT_ROOTS = (Path("/tmp"),)

mcp = FastMCP("Apex Reverse Engineering - Read Only Binary Triage")


def _allowed_roots() -> tuple[Path, ...]:
    raw = os.environ.get("APEX_MCP_ALLOWED_ROOTS", "")
    roots = tuple(Path(item).expanduser().resolve() for item in raw.split(os.pathsep) if item)
    return roots or tuple(root.resolve() for root in DEFAULT_ROOTS)


def _safe_path(path: str) -> Path:
    candidate = Path(path).expanduser().resolve()
    if not candidate.is_file():
        raise ValueError(f"not a regular file: {candidate}")
    if not any(candidate == root or root in candidate.parents for root in _allowed_roots()):
        roots = ", ".join(str(root) for root in _allowed_roots())
        raise PermissionError(f"path is outside APEX_MCP_ALLOWED_ROOTS ({roots})")
    return candidate


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


def _parse(path: Path) -> Any:
    try:
        binary = lief.parse(str(path))
    except Exception as exc:  # LIEF raises format-specific exceptions.
        raise ValueError(f"LIEF could not parse {path.name}: {exc}") from exc
    if binary is None:
        raise ValueError(f"LIEF did not recognize a supported binary format: {path.name}")
    return binary


def _hash(path: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    info = path.stat()
    return {"path": str(path), "size_bytes": info.st_size, "sha256": digest.hexdigest()}


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
    """Return the SHA-256, size, and absolute path without modifying the file."""
    return _hash(_safe_path(path))


@mcp.tool()
def apex_binary_overview(path: str) -> dict[str, Any]:
    """Return parsed format, architecture, entry point, and binary-level counts."""
    safe = _safe_path(path)
    binary = _parse(safe)
    header = _attr(binary, "header", {})
    sections = _attr(binary, "sections", []) or []
    imports = _attr(binary, "imports", []) or []
    exports = _attr(binary, "exported_functions", []) or []
    result = _hash(safe)
    result.update(
        {
            "format": _attr(binary, "format"),
            "architecture": _attr(header, "machine_type") or _attr(header, "machine"),
            "entrypoint": _attr(binary, "entrypoint"),
            "imagebase": _attr(binary, "imagebase"),
            "section_count": len(sections),
            "import_library_count": len(imports),
            "export_count": len(exports),
            "has_nx": _attr(binary, "has_nx"),
            "has_pie": _attr(binary, "is_pie"),
            "has_canary": _attr(binary, "has_stack_canary"),
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
    for index, section in enumerate(_attr(binary, "sections", []) or []):
        if index >= limit:
            break
        result.append(
            {
                "name": _attr(section, "name"),
                "offset": _attr(section, "offset"),
                "size": _attr(section, "size"),
                "virtual_address": _attr(section, "virtual_address"),
                "virtual_size": _attr(section, "virtual_size"),
                "entropy": _attr(section, "entropy"),
                "permissions": _attr(section, "permissions"),
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
    for library_index, library in enumerate(_attr(binary, "imports", []) or []):
        if library_index >= limit:
            break
        entries = []
        for entry_index, entry in enumerate(_attr(library, "entries", []) or []):
            if entry_index >= limit:
                break
            entries.append({"name": _attr(entry, "name"), "ordinal": _attr(entry, "ordinal")})
        imports.append({"library": _attr(library, "name"), "entries": entries})
    exports = []
    for export_index, item in enumerate(_attr(binary, "exported_functions", []) or []):
        if export_index >= limit:
            break
        exports.append({"name": _attr(item, "name"), "address": _attr(item, "address"), "ordinal": _attr(item, "ordinal")})
    return {"path": str(safe), "imports": imports, "exports": exports}


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
    return {"path": str(safe), "scanned_bytes": len(data), "strings": values, "truncated": len(values) >= limit}


@mcp.tool()
def apex_read_bytes(path: str, offset: int = 0, length: int = 256) -> dict[str, Any]:
    """Return a bounded hex preview from a file for evidence-backed byte inspection."""
    safe = _safe_path(path)
    data = _read_range(safe, offset, length)
    return {"path": str(safe), "offset": offset, "length": len(data), "hex": data.hex(), "eof": len(data) < length}


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
    return {"path": str(safe), "offset": offset, "scanned_bytes": len(data), "architecture": architecture, "mode": mode, "instructions": instructions}


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
        return {"path": str(safe), "offset": offset, "scanned_bytes": 0, "entropy": 0.0}
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    entropy = -sum((count / total) * __import__("math").log2(count / total) for count in counts if count)
    return {"path": str(safe), "offset": offset, "scanned_bytes": total, "entropy": round(entropy, 6), "max_entropy": 8.0}


@mcp.tool()
def apex_yara_scan(path: str, rules_text: str, timeout_seconds: int = 10) -> dict[str, Any]:
    """Scan an authorized file with inline YARA rules; rules cannot include external files."""
    safe = _safe_path(path)
    if not rules_text.strip() or len(rules_text) > 100_000:
        raise ValueError("rules_text must be non-empty and <= 100000 characters")
    if not 1 <= timeout_seconds <= 60:
        raise ValueError("timeout_seconds must be between 1 and 60")
    try:
        rules = yara.compile(source=rules_text, includes=False)
        matches = rules.match(str(safe), timeout=timeout_seconds)
    except Exception as exc:
        raise ValueError(f"YARA scan failed: {exc}") from exc
    return {"path": str(safe), "matches": [{"rule": match.rule, "namespace": match.namespace, "tags": list(match.tags)} for match in matches]}


@mcp.tool()
def apex_toolchain_status() -> dict[str, Any]:
    """Report available local reverse-engineering backends without running an analyzed sample."""
    commands = [
        "gdb",
        "gdbserver",
        "radare2",
        "yara",
        "objdump",
        "readelf",
        "strings",
        "qemu-aarch64",
        "qemu-x86_64",
        "frida",
        "frida-trace",
        "capa",
        "floss",
        "binwalk",
    ]
    return {
        "mcp": "available",
        "python_modules": {
            "lief": getattr(lief, "__version__", "available"),
            "capstone": getattr(capstone, "__version__", "available"),
            "yara": getattr(yara, "__version__", "available"),
        },
        "commands": {name: shutil.which(name) for name in commands},
        "read_only_server": True,
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    mcp.run(transport="stdio")
