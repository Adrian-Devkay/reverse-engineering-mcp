# Supply-chain and release verification

This skill records dependency and source integrity separately from capability
claims. The bundled core lock is `requirements-mcp.lock.txt`, and its metadata
is mirrored in `provenance/dependency-lock.json`. The lock currently targets
Linux x86_64 with CPython 3.13 and includes wheel hashes; another platform or
Python minor version needs its own reviewed lock. The optional analysis
lock is a separate exact-version snapshot for the same platform, but does not
yet carry artifact hashes. An operator must point the probe at that environment
and create platform-specific artifact hashes before treating those backends as
release- or CI-grade dependencies.

## Check the core lock

Run:

```bash
python scripts/provenance_report.py check-lock
```

The check compares the requirements-file digest and exact installed core
versions, confirms that the core lock file contains artifact hashes, and reports
optional-version mismatches separately. It does not download packages and it
does not claim that an optional backend is present unless the explicitly
configured analysis environment matches the optional lock.

For the locked host profile, installation must use the lock and hash checks:

```bash
python -m pip install --require-hashes --only-binary=:all: -r requirements-mcp.lock.txt
```

## Generate an SBOM

Create a path-free CycloneDX report once per release or case:

```bash
python scripts/provenance_report.py sbom --output provenance/sbom.cdx.json
```

The SBOM contains exact locked package names and versions only. It intentionally
does not include home directories, virtual-environment paths, environment
variables, credentials, or package-manager caches.

## Verify source integrity

Create the release-tree manifest once the source is final, then verify it before
packaging:

```bash
python scripts/source_integrity.py create
python scripts/source_integrity.py verify
```

The manifest uses relative paths and SHA-256. It detects changes to the tracked
tree; it is an integrity check, not proof of publisher identity. Never treat a
manifest as trusted until its detached signature has been verified with an
independently obtained public key.

## Verify a detached signature

The fixed verifier supports OpenSSL SHA-256 signatures and `pkeyutl` public-key
verification. It accepts only explicit files and never invokes a shell:

```bash
python scripts/verify_signature.py \
  --manifest provenance/source-manifest.json \
  --signature provenance/source-manifest.sig \
  --public-key /trusted/release-key.pem
```

The public key and signature are trust inputs supplied by the release operator;
this skill does not generate or silently install trust anchors. A missing key,
invalid signature, or unavailable verifier is a failed verification, not a
warning to ignore.

## Module boundary

- Core: read-only MCP, fixed static object-tool adapter, evidence manifests,
  provenance checks, and offline analysis guidance.
- Optional Web Recon: a separate GET-only, scope-manifest-gated network module;
  it is never activated by merely loading the core skill.
- Optional Lab: a separate Docker/Podman module; it requires an authorized case,
  an image pinned by `@sha256:` digest, a fixed profile, and explicit execution
  approval. Tagged images and automatic pulls are unsupported.

External Ghidra, Frida, QEMU, fuzzer, mobile, and forensic tools remain
probe-only until their own reviewed adapter, isolation, and evidence contract
exists. A lock or SBOM does not grant authorization to use any target or tool.
