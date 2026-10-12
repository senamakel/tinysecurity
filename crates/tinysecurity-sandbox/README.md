# Scoped sandbox planning

This internal crate owns declarative plan selection and a bounded opaque
artifact registry. Hosts use `tinysecurity-bus` and the native module's `Plan2`,
`EvaluateSandboxApproval2` and `ConsumeSandboxPlan2` ports.

Initialization fixes host provenance, subject, deployment, mode settings,
capability identities and ceilings. SaaS and untrusted sources require kernel
isolation with enforced filesystem protection. Every requested hard constraint
must be enforced. Noop, BestEffort, unsupported CPU time, unvalidated proxy
routing, widened ceilings and credential-covering grants deny.

`ResourceLimits2.cpu_time_ms` is CPU time. `cpu_millicores` is thousandths of a
core. Legacy `ResourceLimits.cpu_millis` remains CPU time; TinyBox 0.1.17's
`cpu_millis` is millicores and cannot satisfy that legacy limit.

Host networking requires an exact durable authenticated human Once approval
under the initialized ceiling, never generic automatic or reusable approval.
The module commits sanitized audit before activating an opaque artifact.
Consume validates the full registered artifact, commits its audit, then checks
owner, generation and expiry again before reserving it once. Public fingerprints
are correlations, not authority. Registry capacity is 1024 artifacts, and expired
or failed pending entries are removed. Callback execution holds no policy or
registry lock.

This crate does not launch a process or prove OS isolation. TinyBox must verify
live availability, capability revision and concrete enforcement at the launch
boundary. The loaded native fixture proves planning and admission contracts;
it is not evidence of a confined child. No production gitlink migration is
complete until the owning upstream changes and release artifacts are available.

`ConsumeSandboxPlan2` carries the original typed `Plan2` envelope as well as the
opaque artifact. The host derives that envelope from the exact prepared spawn:
argv, environment, cwd and input belong in its bounded original operation.
The owner validates its canonical binding before audit and again after the
callback; changed operations cannot consume a copied artifact. This does not
replace TinyBox's live isolation and capability checks.
