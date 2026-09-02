# Cryptography, Update Trust, and Supply-Chain Analysis

Use this reference for cryptographic implementations, key handling, signed updates, secure boot, rollback, dependencies, SBOMs, and CVE/GHSA reachability.

## Trust-chain model

Map:

```text
key/material source → verification or derivation → trust decision → privileged action → persistence or deployment
```

Check algorithm, mode, parameters, nonce/IV, randomness, key generation, storage, rotation, revocation, error handling, and downgrade behavior. For JWT, certificates, or signed data, verify issuer, audience, algorithm selection, expiry, key binding, canonicalization, and failure behavior. Do not treat a weak-looking primitive as an impact without a reachable misuse.

For update and boot flows, inspect manifest parsing, signature coverage, root of trust, key rotation, version/rollback checks, recovery mode, staging, atomicity, and post-install privilege. Record whether the evidence came from source, an image, emulation, or a physical device.

## Supply-chain reachability

For a CVE/GHSA or dependency concern:

1. Identify the pinned dependency and affected version range.
2. Confirm the vulnerable component is included in the deployed artifact, not merely declared in a lockfile.
3. Trace whether the vulnerable code path is reachable with the target's inputs and configuration.
4. Check wrappers, patches, feature flags, sandboxing, and compensating controls.
5. Validate with a local fixture or vendor regression test when available.

Record SBOM/provenance, lockfile state, build target, feature flags, and deployment assumptions. Separate theoretical package exposure from exploitable project exposure.

## Safety boundary

Do not extract or publish private keys, bypass license/signature checks on third-party software, flash modified firmware without authorization and recovery, or test update infrastructure in production. Use synthetic keys and disposable images for validation.
