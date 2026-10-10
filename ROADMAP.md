# TinySecurity roadmap

The bootstrap implements conservative policy evaluation, ordered checks,
versioned contracts, SDK init/reinit and native loading. It intentionally does
not close the security extraction tracker.

The [implementation plan](docs/plans/security-module.md) orders the remaining
work: full host policy/command parity, unified redaction, connection-pinned
egress, TinyBox sandbox planning, durable audit/approvals, optional Jev,
native conformance and release gates, reviewed policy expansion, crypto last.

Production OpenHuman callers move only after upstream capabilities are merged,
released and validated with published checksums and native latency budgets.
