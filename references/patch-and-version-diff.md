# Patch and Version Differential Analysis

Use this reference to understand a security fix, compare releases, map affected versions, or detect regression risk in authorized source, bytecode, or binaries.

## Method

1. Pin the comparison endpoints, provenance, build configuration, and symbol/optimization differences.
2. Start with source or commit diff when available, then compare compiled functions, sections, imports, strings, and control flow.
3. Identify changed validation, authorization, parsing, memory, cryptographic, update, or error-handling decisions.
4. Trace the changed decision to its callers and final sink; do not infer impact from a changed line alone.
5. Reproduce the relevant safe control behavior before and after the fix using a local fixture, regression test, or deterministic harness.
6. Map versions using release tags, dependency locks, backports, feature flags, and deployment configuration.

## Evidence standard

Record the exact commit/tag or binary hash, changed function/offset, normalized diff, behavior difference, test input, and interpretation. Treat compiler noise, symbol changes, build timestamps, and unrelated refactors as non-security changes until corroborated.

For a vulnerability fixed by a patch, document:

```text
pre-fix behavior + post-fix behavior + changed trust decision + reachability + affected range
```

For a regression hypothesis, show a previously passing control that fails in the newer version and identify the first change that explains it.

## Safety boundary

Use local copies and read-only comparisons by default. Do not reverse engineer proprietary software outside the approved scope, remove licensing controls, or publish a portable exploit merely because a patch reveals a vulnerable pattern.
