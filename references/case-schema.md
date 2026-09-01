# Case record schema

The case manifest is intentionally small, deterministic, and safe to diff. `scripts/init_case.py` creates the base record; analysts may extend it without changing the original artifact.

## Required top-level fields

```json
{
  "schema": "reverse-engineering-mcp/case-v1",
  "case_id": "case-identifier",
  "created_utc": "2026-01-01T00:00:00+00:00",
  "scope": {
    "authorization": "owner-approved assessment",
    "target": "case-local artifact reference",
    "exclusions": ["external network", "production services"]
  },
  "artifact": {
    "path": "local path kept outside the public repository",
    "size_bytes": 0,
    "sha256": "hex digest",
    "format": "ELF or PE or unknown",
    "architecture": "x86_64 or unknown",
    "mtime_utc": "2026-01-01T00:00:00+00:00"
  },
  "environment": {
    "platform": "isolated lab description",
    "python": "version",
    "tools": {}
  },
  "actions": [],
  "findings": []
}
```

## Action record

Each material action should include `timestamp_utc`, `kind`, `tool`, `command_or_operation`, `inputs`, `outputs`, `result`, and `safety_boundary`. Prefer references to output files and hashes over embedding large logs.

## Finding record

Each finding should include `id`, `claim`, `classification`, `status`, `confidence`, `impact`, `evidence`, `alternatives`, `reproduction`, and `remediation_or_detection`. Evidence entries should name the artifact hash plus a file, offset/address, trace event, packet, or experiment.

## Privacy rules

Case records may contain local paths, target identifiers, and timestamps, so keep them in ignored case directories. Redact credentials, access tokens, personal data, private URLs, and unnecessary host identifiers before sharing. Never copy a case record into the public repository without an explicit review.
