# TinySecurity roadmap

Tracked by [OpenHuman #7328](https://github.com/tinyhumansai/openhuman/issues/7328).

## Delivered

Policy evaluation and ordered checks, scoped and immutable path policies, redaction
(including the boot diagnostic floor, [ADR 0007](docs/adr/0007-boot-diagnostic-redaction-floor.md)),
scoped egress grants, durable exact approvals, optional judge scoring, sandbox
planning, audit, confidential device, secret, cipher, password, keyring and pairing
members, and a CI-enforced release latency budget ([performance](docs/performance.md)).
`max_cost_per_day_cents` was removed from the contract ([ADR 0006](docs/adr/0006-remove-max-cost-per-day.md)).

## Open

- Confidential delivery to an ordinary (non-native) admitted host callback, needed
  for config-cipher plaintext delivery and pairing `Begin`/`Verify` (TinyBus gap).
- Native conformance on macOS and Windows runners for device and secret members.
- Fault-injection and timeout latching conformance in the SDK.
- Windows alias, ADS and device-path handling and rich shell grammar parity.
- Calls-per-turn measurement against a representative OpenHuman workload.

Host callers move to a member only after it is merged, released and validated with
published checksums and the native latency budget. See [MODULE.md](MODULE.md) for the
current surface.
