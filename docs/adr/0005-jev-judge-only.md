# 5. Use Jev only to judge an existing approval request

- Status: Accepted
- Date: 2026-10-10

## Context

Probabilistic scores do not establish user permission. A judge sees untrusted
tool content and can fail, leak secrets or overgeneralize past decisions.

## Decision

Jev is off by default with explicit per-origin opt-in. It can change only
RequireApproval to Allow, never Deny or a mandatory privacy/isolation rule.
Redaction precedes submission. Independent intent, reversibility and exfiltration
questions feed locally owned thresholds and bounded request budgets.
Credentials arrive through init/reinit only and have no secret Debug output.

Timeout, error, malformed response, low confidence or unavailable judge keeps
human approval required. An unavailable human channel denies. Decisions are
bound to the original verified caller and call fingerprint. Judge caches cannot
override fresh checks of mutable grants, rate state or execution conditions.
Every verdict records sanitized scores, thresholds and auto:jev attribution;
auto_approve_all also audits.

## Consequences

Local stub judges test every failure path on Linux, macOS and Windows.
The module owns threshold and budget semantics; inference clients only return
scores. SaaS must provide a verified approval channel or deny unresolved work.
