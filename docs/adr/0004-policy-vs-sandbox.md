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
