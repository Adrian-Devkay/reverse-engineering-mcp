# Reverse-engineering report template

Copy this template into a case directory and replace bracketed fields. Do not publish a report containing private sample data, credentials, live infrastructure, or unnecessary host identifiers.

```markdown
# Reverse-engineering report: [case ID]

## Executive summary

- Authorization and scope: [basis, target, exclusions]
- Overall result: [one paragraph]
- Confidence: [high/medium/low and why]

## Target and integrity

| Field | Value |
| --- | --- |
| Artifact | [name/provenance] |
| SHA-256 | [digest] |
| Size | [bytes] |
| Format/architecture | [value] |
| Related specimens | [hashes or none] |

## Environment and containment

- Lab or host boundary: [description]
- Network policy: [disabled/simulated/authorized]
- Snapshot or reset point: [identifier]
- Tool versions: [list]
- Unperformed actions: [list]

## Method and timeline

| Time | Action | Input | Output/evidence | Result |
| --- | --- | --- | --- | --- |
| [UTC] | [operation] | [hash/path] | [file/event] | [result] |

## Findings

### [F-001] [precise claim]

- Classification: [behavior/vulnerability/compatibility/unknown]
- Status: [confirmed/needs reproduction/blocked/disproven]
- Confidence: [high/medium/low]
- Root cause or behavior: [explanation]
- Reachability and preconditions: [details]
- Impact: [deployment-specific impact]
- Evidence:
  1. [static/runtime/format evidence with location]
  2. [independent corroboration]
- Alternatives not ruled out: [list]
- Safe reproduction: [minimal authorized procedure or not available]
- Remediation or detection: [guidance]

## Coverage and limitations

- Tested: [surfaces]
- Not tested: [surfaces]
- Blocking constraints: [missing symbols, unsupported architecture, etc.]

## Open questions and next experiments

1. [question, proposed test, expected evidence]

## Reproducibility appendix

- Case manifest: [path/hash]
- Commands or UI operations: [safe references]
- Traces/captures: [path/hash]
- Derived artifacts: [path/hash and transformation]
```
