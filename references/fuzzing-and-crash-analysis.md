# Fuzzing and Crash Analysis

Use this reference for parser, memory-safety, deserialization, protocol, and input-validation hypotheses in an authorized local target. The objective is a deterministic root-cause and exploitability assessment, not an unbounded crash campaign.

## Harness contract

Record the target version/commit, entry point, input format, build flags, sanitizer/tool versions, seed corpus provenance, CPU/memory/wall-clock limits, network policy, and stop conditions. Prefer a self-contained harness that does not contact external services, write outside a disposable directory, or use real credentials.

Choose the smallest suitable strategy:

- structured or grammar-based mutation for formats and protocols;
- coverage-guided fuzzing for a stable local function or parser;
- differential fuzzing for two versions, implementations, or configurations;
- property tests for invariants such as bounds, round trips, canonicalization, and authorization decisions.

Use AFL++, libFuzzer, Honggfuzz, or an equivalent only if available and appropriate. Pin the seed and record the exact command. Cap parallelism and stop on the first useful crash cluster when the question is answered.

## Crash triage

For each candidate:

1. Preserve the original input and a minimized reproducer.
2. Capture signal/exception, stack trace, registers or managed exception, sanitizer report, build identity, and deterministic replay result.
3. Deduplicate by normalized top frames, allocation/object identity, sanitizer class, and input path; do not count repeated symptoms as separate bugs.
4. Separate input rejection, assertion failure, resource exhaustion, denial of service, memory corruption, and code-execution potential.
5. Corroborate the root cause with source, disassembly, a second build/configuration, or a controlled trace.

A crash is not automatically exploitable. State whether control of instruction pointer, data flow, privilege, or protected memory was demonstrated; otherwise label exploitability unknown.

## Safety boundary

Do not fuzz production, third-party services, authentication endpoints, or real user data. Do not generate weaponized payloads, persistence, shellcode, or exploit chains. Keep resource-exhaustion experiments local and explicitly approved. Redact secrets and personal data from inputs, stack traces, and reports.

## Required evidence

```text
target/version
harness_and_entry_point
seed_provenance
limits_and_environment
input_hash
replay_command
observed_signal_or_exception
sanitizer_or_trace_evidence
root_cause_location
deduplication_basis
exploitability: demonstrated | plausible | unknown | not_applicable
impact_and_scope
remediation_and_regression_test
```
