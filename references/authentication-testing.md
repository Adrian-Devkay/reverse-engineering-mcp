# Authentication and Credential-Control Testing

Use this reference only for an owned application, local lab, self-managed instance, or explicitly approved test account and time window. The objective is to characterize defensive controls, not to obtain access to accounts.

## Scope and safety contract

Before testing, record the target, approved accounts, permitted endpoints, time window, request-rate ceiling, network boundary, and stop conditions. Use synthetic passwords and disposable accounts. Never use leaked, third-party, or real-user credential lists; never test accounts outside the approved scope; never bypass MFA or recovery controls to gain access.

Password attempts must be bounded and deterministic. Prefer one or a few invalid attempts per account to establish a control response. Stop as soon as rate limiting, lockout, MFA enforcement, or alerting behavior is characterized. Do not perform distributed spraying, credential stuffing at scale, password cracking, or denial-of-service testing.

## Control matrix

Assess only the dimensions relevant to the hypothesis:

| Control | Safe observation | Evidence to preserve |
|---|---|---|
| Rate limiting | response and retry behavior after a minimal invalid-attempt sequence | timestamps, status, retry metadata, bounded count |
| Account lockout or throttling | whether the synthetic account is slowed or locked, and how recovery works | state transition, reset path, audit event |
| MFA | whether a second factor is required for login and sensitive actions | challenge state, factor binding, denial path |
| Password policy | minimum length, reuse/history, breached-password control, strength validation | policy response, not the submitted secret |
| Reset flow | token expiry, one-time use, user/session binding, post-reset session invalidation | redacted token metadata, state transitions |
| Session/token lifecycle | logout, password change, role change, revocation, expiry, rotation | pre/post request authorization result |
| Detection | alert, audit event, IP/device signal, notification, or review workflow | redacted event type and timestamp |

Use a positive control where the test account is expected to authenticate and a negative control with a deliberately invalid synthetic credential. Keep the only changed variable explicit.

## Source and binary review

Trace authentication from input to the final decision:

1. Credential parsing and normalization, including Unicode, case, whitespace, and duplicate parameters.
2. Password verification, hash selection, cost configuration, breached-password checks, and timing behavior.
3. Principal lookup and account state: disabled, suspended, unverified, locked, expired, or tenant-restricted.
4. MFA and step-up decisions, backup codes, remembered devices, recovery paths, and trusted-session state.
5. Rate-limit keys and storage: account, IP, device, tenant, token, route, and proxy-derived identity.
6. Session or token issuance, rotation, revocation, audience, expiry, and binding to the authenticated principal.
7. Alternate paths: API tokens, OAuth, SSO, mobile endpoints, GraphQL, password reset, invitation acceptance, service accounts, background jobs, and legacy login routes.
8. Logging and alerting sinks; ensure secrets, password material, reset tokens, and session values are not written in plaintext.

For native or managed clients, distinguish client-side checks from server-side authentication. Inspect secure storage, exported authentication components, IPC caller identity, token handling, certificate validation, and offline/remembered-login behavior.

## SRC-quality finding gate

Do not report a credential-control issue as a confirmed vulnerability until the evidence shows:

- exact authorized scope and affected version;
- synthetic account and controlled test conditions;
- expected secure behavior and the observed deviation;
- the smallest reproducible sequence, with no real credentials or secrets;
- concrete impact, such as account takeover conditions, bypass of a required factor, durable session access, or a meaningful loss of protective control;
- why the result is not a documented policy, user-configurable setting, expected recovery behavior, or test-environment artifact;
- remediation and a regression test.

An error message, different response timing without impact, weak-looking password policy, or a theoretical missing rate limit is not automatically an SRC finding. Keep it as a hardening note unless unauthorized access or a meaningful security boundary failure is demonstrated.

## Reporting fields

```text
finding_id
target/version
authorized_accounts_and_roles
tested_control
positive_control_result
negative_control_result
bounded_attempt_count_and_rate
observed_state_transition
security_impact
source_or_trace_locations
redaction_notes
confidence
limitations
remediation_and_regression_test
```

Never store passwords, password lists, cookies, session tokens, reset tokens, MFA secrets, OAuth values, private keys, or unrelated personal data in the case record.
