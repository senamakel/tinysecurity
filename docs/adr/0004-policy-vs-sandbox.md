# 4. Decide sandbox placement here and execute in TinyBox

- Status: Accepted
- Date: 2026-10-10

## Context

Policy classification and isolation execution currently overlap across host
helpers and sandbox crates, leaving some spawners unconfined.

## Decision

TinySecurity owns command/path classification and declarative SandboxPlan
decisions. TinyBox owns process launch, isolation backends and capability
verification. OpenHuman translates plans to TinyBox contracts and presents
results. SaaS cannot disable isolation. Untrusted sources refuse Noop;
credential stores never become grants. Unsupported isolation denies.

Network policy likewise needs an execution seam. A URL verdict is insufficient
for DNS rebinding defense: the transport must connect to approved addresses,
preserve TLS hostname checks and revalidate/pin redirects. A transport unable
to enforce this must use verified egress mediation or deny protected access.

## Consequences

TinyBox changes land upstream before host gitlinks move. Every spawner is
inventoried and tested. Unit tests can validate plans, but actual OS isolation
and transport pinning need native integration tests on supported platforms.

## Scoped planning admission (contract 1.9)

The initialized host registers immutable provenance and capability declarations.
The planner checks enforced constraints and immutable ceilings, then commits an
exact sanitized audit before activating a bounded opaque artifact. A public
fingerprint cannot mint authority. Consume audits and atomically reserves that
artifact once with fresh owner, generation and expiry checks. Host networking
requires an authenticated exact human Once decision, including when Jev is
qualified for generic automatic approval.

This admission port does not attest a running child. TinyBox remains responsible
for live capability validation and OS enforcement at launch; OpenHuman's later
adapter binds managed child and warm-pool reuse to the artifact's full scope.
