# Security policy

## Supported reports

Report vulnerabilities in this skill, its local MCP server, or its documentation privately through the repository's GitHub security reporting mechanism when available. Do not publish exploit code, credentials, private samples, or live infrastructure details in a public issue.

## Scope boundaries

The local MCP server is designed for bounded, read-only artifact triage. A report should include the affected file/version, a minimal safe reproduction, impact, and suggested remediation. Do not test against third-party systems or submit samples containing secrets.

## Safe analysis

Unknown code must be analyzed in an isolated, revertible lab with credentials removed and networking disabled or simulated. Firmware changes, production interaction, external network access, and exploit testing require explicit authorization and a recovery plan.
