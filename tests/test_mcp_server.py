from pathlib import Path

import pytest

import mcp_server


def test_safe_path_accepts_allowlisted_file(tmp_path, monkeypatch):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample")
    monkeypatch.setenv("APEX_MCP_ALLOWED_ROOTS", str(tmp_path))

    assert mcp_server._safe_path(str(sample)) == sample.resolve()


def test_safe_path_rejects_file_outside_allowlist(tmp_path, monkeypatch):
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside.bin"
    allowed.mkdir()
    outside.write_bytes(b"sample")
    monkeypatch.setenv("APEX_MCP_ALLOWED_ROOTS", str(allowed))

    with pytest.raises(PermissionError):
        mcp_server._safe_path(str(outside))


def test_bounded_byte_reads_are_enforced(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample")

    with pytest.raises(ValueError):
        mcp_server._read_range(sample, 0, mcp_server.MAX_PREVIEW_BYTES + 1)


def test_string_extraction_supports_ascii_and_utf16le():
    data = b"prefix\x00ASCII_VALUE\x00W\x00I\x00D\x00E\x00_\x00V\x00A\x00L\x00U\x00E\x00\x00suffix"

    values = mcp_server._strings(data, 4)
    rendered = {item["value"] for item in values}

    assert "ASCII_VALUE" in rendered
    assert "WIDE_VALUE" in rendered
    assert "EWIDE_VALUE" not in rendered


def test_enum_rendering_prefers_symbolic_name():
    class Example:
        name = "SYMBOLIC"

    assert mcp_server._enum_value(Example()) == "SYMBOLIC"
