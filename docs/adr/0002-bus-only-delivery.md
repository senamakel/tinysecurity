# 2. Deliver policy through a native bus module

- Status: Accepted
- Date: 2026-10-10

## Context

Linking security engines into OpenHuman shares their dependency graph and
permits callers to bypass the intended module admission boundary.

## Decision

Hosts depend only on `tinysecurity-bus`, with `serde` and `thiserror` as its
normal dependencies. Native modules contain all behavior and private engines.
Host persistence, prompts, audit forwarding and consent use typed bus callbacks.
Credential configuration crosses init/reinit only, with redacted Debug output.
Requests carry verified host context rather than task-locals or model claims.

OpenHuman loads through digest admission and `attested_proxy`. Capability
migration waits for an upstream release with published archives and checksums.
Only implemented members are advertised. Bootstrap is real Evaluate/Check
behavior, not an empty set of future engine crates.

## Consequences

CI must enforce transport-free contracts and the host dependency boundary.
Hot-path measurements precede migration; batching and safe caching address
latency without linking engines. Golden wire fixtures and version checks are
required because the native ABI cannot enforce Rust type compatibility alone.
