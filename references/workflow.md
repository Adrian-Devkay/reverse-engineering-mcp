# Investigation workflow

This document turns the core skill contract into a repeatable case procedure. The exact tools may vary by target; the evidence gates do not.

## 0. Scope gate

Record:

- authorization basis and owner;
- exact artifact, device, service, or specimen identifiers;
- allowed techniques and time window;
- network policy and data-handling rules;
- exclusions, stop conditions, and reporting audience.

If any item is missing and the next action could execute code, transmit data, change state, or bypass a control, pause and request the missing boundary.

## 1. Intake and preservation

Work in a case directory that is separate from the original artifact. Hash the original before copying. Preserve the copy relationship, source/provenance, file timestamps, acquisition method, and chain-of-custody notes. Do not normalize, unpack, repair, or patch the original.

**Exit condition:** the artifact can be identified later by SHA-256 and the analyst can explain where every derived file came from.

## 2. Triage

Collect format, architecture, entry point, sections/segments, imports/exports, symbols, strings, entropy, signing, mitigation flags, compiler/packer clues, and embedded content. Use bounded reads and record tool versions. Negative results are evidence only within the tested coverage.

**Exit condition:** the analyst has a target classification and a short list of behavior hypotheses or unanswered questions.

## 3. Static reconstruction

Recover the program model in layers:

1. map modules, trust boundaries, and externally controlled inputs;
2. identify parsers, dispatchers, state transitions, storage, IPC, update logic, and privilege changes;
3. recover relevant functions and call/data-flow paths;
4. confirm important decompiler claims with assembly, bytes, types, and cross-references;
5. record unresolved type, packing, anti-analysis, and architecture uncertainty.

**Exit condition:** every important hypothesis has a candidate static path and a proposed discriminating test.

## 4. Hypothesis testing

Prefer the smallest test that distinguishes competing explanations. Examples include a second disassembler view, a controlled input pair, a bounded symbolic path, a read-only emulator observation, or an isolated trace. Define expected observations before running the test.

**Exit condition:** the hypothesis is confirmed, weakened, disproven, or explicitly blocked with the missing evidence named.

## 5. Controlled dynamic analysis

Only run inside a disposable VM or equivalent isolation with no credentials, sensitive mounts, or unrestricted network. Snapshot first. Capture only what answers the question: process tree, syscalls, memory regions, files, IPC, registry/configuration, or packets. Store raw traces separately from interpretations.

**Exit condition:** the trace is tied to the exact artifact hash, environment, command, isolation boundary, and timestamp.

## 6. Correlation

For each material conclusion, connect:

```text
input/trust boundary -> state transition -> code location -> observable effect -> security or compatibility impact
```

Resolve disagreements between static and dynamic views before increasing confidence. If they cannot be resolved, report both and lower confidence.

## 7. Finding triage

For a suspected vulnerability, answer in order:

1. What is the root cause?
2. Is attacker-controlled data able to reach it?
3. What preconditions and configurations are required?
4. Is the behavior reproducible with a minimal safe input?
5. What is the impact in the actual deployment?
6. What mitigations, detections, or patches reduce risk?

Do not equate a dangerous-looking instruction, a crash, or a reachable local path with remote exploitability.

## 8. Closeout

Record tested and untested surfaces, tool versions, failed approaches, coverage limits, open questions, and recommended next experiments. Freeze the original evidence and export a concise report plus machine-readable case data. Never commit case data or samples to this public skill repository.
