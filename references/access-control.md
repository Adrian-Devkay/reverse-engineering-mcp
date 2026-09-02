# Access-Control and Privilege-Boundary Analysis

Use this reference when the target exposes accounts, roles, tenants, projects, teams, resources, administrative actions, APIs, GraphQL, downloads, webhooks, background jobs, or other authorization boundaries.

## Terms and proof standard

- **Vertical privilege escalation:** an actor with a lower privilege level performs an action or reaches data reserved for a higher privilege level.
- **Horizontal privilege escalation:** an actor at the same nominal privilege level reads, changes, deletes, exports, or triggers an action against another actor's object without authorization.
- **BOLA/IDOR:** an object-level authorization failure. An identifier being guessable is not itself the vulnerability; prove that the server accepts an unauthorized object/action combination.
- **Cross-tenant escape:** an actor crosses a tenant, organization, project, or namespace boundary. Treat it as a high-priority horizontal boundary even if the roles are identical.

Classify the result only after establishing all five dimensions:

```text
actor/principal + tenant/context + action + resource/object + server-side decision
```

Client-side hiding, a different error message, an exposed identifier, or a UI-only restriction is not proof of privilege escalation without a server-side authorization failure and meaningful impact.

## Authorization model

Build a compact matrix before testing. Use synthetic accounts and objects whenever possible.

| Dimension | Minimum cases |
|---|---|
| Actor | unauthenticated, ordinary member, object owner, same-role non-owner, manager, administrator, service token |
| Tenant/context | same tenant, sibling project/team, different tenant, suspended or archived context |
| Resource | actor-owned, same-role peer-owned, privileged-owned, nonexistent, deleted or transferred |
| Action | create, list, read, update, delete, export/download, approve, invite, role change, secret/webhook test, resend, administrative mutation |
| Delivery path | REST, GraphQL, form/UI endpoint, file/download route, WebSocket/RPC, async worker, import/export, notification or webhook callback |

Record the expected decision for each relevant cell. The key comparisons are:

```text
lower-role actor vs privileged action/object       -> vertical boundary
same-role actor vs peer-owned object               -> horizontal boundary
same-role actor vs other-tenant object             -> tenant boundary
authorized request vs minimally changed identifier -> object-scope boundary
authorized synchronous request vs queued execution -> time-of-check boundary
```

## Source and binary tracing

Trace the request or message through every enforcement point to the final sink:

1. Identify principal construction: session, OAuth/JWT claims, API token, service account, impersonation, or worker identity.
2. Identify the action and object from route parameters, JSON fields, GraphQL arguments, message payloads, file paths, or IPC inputs.
3. Locate function-level checks: route guards, middleware, policy methods, capability checks, permission bitmaps, role comparisons, and feature gates.
4. Locate object-level checks: tenant/project scoping, owner predicates, policy `can?`/`authorize` calls, query scopes, repository filters, and parent-child relationship checks.
5. Follow the data/action sink: controller mutation, serializer, download, export, secret read, webhook trigger, job enqueue, worker perform, or external side effect.
6. Compare alternate paths that may skip the primary check: bulk endpoints, GraphQL fields, REST method variants, aliases, imports, retries, resend/test endpoints, internal APIs, and background jobs.

For native or managed applications, include privilege transitions, IPC caller identity, exported components, file ownership, sandbox tokens, capability checks, and trust decisions in the same model. Decompiler output is a hypothesis; corroborate it with call sites, validation branches, symbols, traces, or controlled behavior.

## Safe differential validation

Only test a target that is explicitly authorized and use a local/self-managed instance or an approved test account. Keep the test bounded:

- Use two or three synthetic principals and the smallest possible set of objects.
- First record a known-allowed control request for the same action and object type.
- Repeat the same request as the minimally different unauthorized actor.
- Change one dimension at a time: actor, tenant, object identifier, role claim, HTTP method, content type, or delivery path.
- Use read-only checks first; for writes, use disposable objects and reversible values. Avoid deletion, mass enumeration, role changes, secret retrieval, or external callbacks unless explicitly approved.
- Preserve status code, response body shape, returned object identifiers, side effects, audit events, and server logs with secrets and personal data redacted.
- Stop once the boundary is proven. Do not expand from one confirmed object to broad enumeration.

Useful negative controls include a nonexistent object, an authorized peer object, a revoked session/token, a stale role, and an object in another tenant. A negative control that is denied helps distinguish a real scope failure from a route or identifier mistake.

## Common bypass surfaces to inspect

Inspect only those relevant to the target; do not spray variants against a live service:

- route/controller checks present on read but missing on update, delete, export, test, resend, or bulk actions;
- ORM queries that load by global ID before applying tenant or parent scope;
- serializers or GraphQL resolvers that expose fields without the same policy as mutations;
- downloads, previews, raw attachments, archive endpoints, and signed URL generation;
- background jobs that trust a user-supplied object ID and do not revalidate authorization at perform time;
- webhook, notification, import/export, and retry paths that execute with a broader service identity;
- alternate HTTP methods, content types, duplicate parameters, path normalization, encoded identifiers, aliases, and legacy routes;
- GraphQL aliases, fragments, batched operations, persisted queries, subscriptions, and field-level authorization;
- tenant/org headers, implicit default contexts, project transfers, membership changes, suspended users, and cached authorization decisions;
- native IPC or plugin bridges where the client can select a privileged operation or object without a server-side capability check.

These are hypotheses to test against an authorized local target, not a list of production attack instructions.

## SRC-quality evidence gate

Do not label or submit a privilege-escalation finding until the evidence contains:

1. **Scope:** exact product/version/endpoint or binary surface, authorization basis, and exclusions.
2. **Actors:** concrete low-privilege or same-role principals and their effective permissions; do not include credentials or personal data.
3. **Control pair:** a known-allowed request and the minimally changed unauthorized request.
4. **Causal chain:** input/identifier → missing or incorrect policy/scope decision → unauthorized sink.
5. **Impact:** what protected data or action was actually reached, with quantity bounded and evidence redacted.
6. **Reproduction:** clean, deterministic steps that work from a fresh authorized lab or approved test account.
7. **Boundary:** why the result is not an intended admin setting, delegated permission, stale cache, UI-only behavior, or duplicate.
8. **Remediation:** the narrow policy/scope fix and regression test that would prevent recurrence.

If only a missing check, a suspicious route, a client-side restriction, a 200 response with no protected data, or a theoretical IDOR is shown, report it as an unconfirmed hypothesis or hardening note—not as a confirmed SRC vulnerability.

## Reporting fields

For each candidate, store:

```text
finding_id
classification: vertical | horizontal | cross-tenant | BOLA/IDOR | unknown
target/version
actor_context
tenant_context
resource_and_action
allowed_control
unauthorized_result
source_or_trace_locations
observed_impact
confidence
limitations
safe_reproduction
remediation_and_regression_test
```

Separate **Observed**, **Inferred**, and **Unknown** facts. Hash or redact identifiers when they are not needed to reproduce the result, and never place tokens, cookies, OAuth values, private keys, or unrelated personal data in the case record.
