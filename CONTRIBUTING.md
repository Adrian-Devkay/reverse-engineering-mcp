# Contributing

Thank you for improving Reverse engineering-mcp. Contributions should improve analysis decisions, evidence quality, reproducibility, or safety without expanding authorization implicitly.

## Before opening a pull request

1. Keep the skill name and frontmatter valid.
2. Keep instructions specific to reverse-engineering decisions; remove generic filler.
3. Do not include samples, credentials, logs, private identifiers, host-specific paths, or generated case data.
4. Add or update tests for changed code.
5. Run the checks from the README and explain any intentional limitation.

## Pull request expectations

Describe the user-facing problem, the decision or workflow it improves, the evidence used to validate it, and any new safety boundary. Documentation changes should include the affected target mode and a reproduction path that is safe to share.

## Scope

This project supports authorized defensive research, interoperability, incident response, malware triage, and vulnerability analysis. It does not accept changes whose primary purpose is unauthorized access, credential theft, persistence, evasion, destructive action, exfiltration, or bypassing security controls.
