# TinySecurity roadmap

The current bootstrap PR implements conservative policy evaluation, ordered checks,
versioned wire contracts, SDK init/reinit and native loading. Publishing those
contracts/artifacts remains pending upstream review and release. It intentionally does
not close the security extraction tracker.

The [implementation plan](docs/plans/security-module.md) orders the remaining
work: full host policy/command parity, unified redaction, connection-pinned
egress, TinyBox sandbox planning, durable audit/approvals, optional Jev,
native conformance and release gates, reviewed policy expansion, crypto last.

Production OpenHuman callers move only after upstream capabilities are merged,
released and validated with published checksums and native latency budgets.
