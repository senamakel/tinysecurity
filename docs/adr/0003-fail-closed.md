# 3. Deny effects after a module fault

- Status: Accepted
- Date: 2026-10-10

## Context

A missing module or fallback to old policy can turn infrastructure failure
into permission. Retrying a faulted native module in-process is unsafe.

## Decision

Absent, incompatible, uninitialized, faulted or timed-out modules deny external
effects. Faults latch until process restart and fresh attestation. Reinit
cannot clear a fault; no linked fallback exists. Normal policy denial remains
a successful response. Invalid reinit retains the prior policy and generation.

Policy updates invalidate static decisions by generation. Cache permissions
require explicit eligibility and verified context. Mutable approvals, flow
trust, rate accounting and DNS authorization are never reusable solely because
the policy generation has not changed.

The unused host cost-cap setting will be removed with migration. The module
does not claim enforcement without a cost reservation/accounting callback.

## Consequences

Hosts need explicit unhealthy-module diagnostics and denial tests. Availability
loss can interrupt external work. Safe local diagnostics remain possible.
Tests distinguish ordinary denials, rejected config and fatal lifecycle faults.
