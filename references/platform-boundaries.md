# Platform and Isolation-Boundary Analysis

Use this reference for OS privileges, IPC, mobile components, browser extensions, containers, Kubernetes, sandboxes, and local trust-boundary questions.

## Boundary model

For each candidate, record:

```text
principal → capability/token/entitlement → boundary enforcement → object or operation → privileged sink
```

Inspect both declaration and runtime enforcement. A permission present in a manifest or policy is not proof that it protects the final sink; a missing declaration is not proof of impact if the component is unreachable.

## Platform surfaces

- Linux: UID/GID transitions, file capabilities, namespaces, seccomp, cgroups, mount visibility, Unix sockets, polkit, systemd, and set-user-ID boundaries.
- Windows: access tokens, integrity levels, ACLs, services, scheduled tasks, COM/RPC, named objects, AppContainer, and impersonation.
- Android/iOS: exported components, intents/deep links, Binder/XPC, app groups, entitlements, Keychain/Keystore, WebView bridges, signing, and backup/restore boundaries.
- Browser extensions: host permissions, content scripts, message passing, native messaging, storage, and privileged API exposure.
- Containers/Kubernetes: namespace/capability sets, seccomp/AppArmor/SELinux, mounts, service accounts, RBAC, admission, secrets, metadata access, and workload identity.

## Validation

Use a disposable local lab and synthetic principals or workloads. Prefer read-only boundary checks, a known-allowed control, and one minimally changed request or IPC message. For an escape hypothesis, demonstrate the exact boundary crossed and protected sink reached; do not broaden into persistence, credential access, or host exploitation.

Document kernel/runtime version, policy configuration, image or package hash, effective identity, and whether the behavior was observed in source, emulation, or a physical device.
