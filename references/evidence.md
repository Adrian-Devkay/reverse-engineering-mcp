# Evidence and reporting

## Case record

Maintain a small machine-readable record containing:

- case identifier, analyst, authorization basis, scope, and exclusions;
- artifact path or provenance, SHA-256, size, format, architecture, and timestamps;
- host/lab isolation assumptions, snapshots, tool versions, and relevant configuration;
- ordered actions with timestamp, command or UI operation, input, output path, and result;
- findings with evidence references, confidence, impact, and status.

Use UTC timestamps in records when possible. Keep secrets, personal data, and unnecessary live identifiers out of notes and reports.

## Evidence quality

Classify claims as:

- **Observed**: directly present in a file, trace, disassembly, packet, memory view, or repeatable experiment.
- **Inferred**: the best explanation supported by observations but not independently confirmed.
- **Unknown**: plausible but not established with the available artifact or scope.

For important findings, preserve at least two independent anchors when practical, such as a static location plus a runtime trace, or a format hypothesis plus a differential test. Record negative results when they bound the conclusion.

## Report structure

1. Executive summary and authorization/scope.
2. Target inventory and integrity hashes.
3. Environment, containment, and limitations.
4. Method and analysis timeline.
5. Findings ordered by confidence and impact.
6. Evidence table: finding, source, location, reproduction, and interpretation.
7. Remediation, detection, or compatibility guidance.
8. Open questions and recommended next experiments.
9. Reproducibility appendix with safe commands, scripts, offsets, captures, and tool output references.

For a vulnerability report, distinguish technical severity from exploitability in the actual deployment. Do not claim a remotely exploitable condition solely from a suspicious instruction sequence or an unverified crash.
