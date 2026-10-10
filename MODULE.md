# Native security module

The artifact is `tinysecurity-module`, exporting TinyBus ABI v1. Its interface
is `ai.tinyhumans.tinysecurity.Policy`, with object
`/ai/tinyhumans/tinysecurity/Policy` and methods `Evaluate`, `Check`, `PolicyInfo`.
Accepted SDK reinit advances a generation and emits `PolicyChanged`; rejected
configurations retain the old policy and generation. There are no Init/Reinit
RPC methods. Configuration must include `contract_version`, `policy`, and
`judge` (`null` in this bootstrap).

```json
{
  "contract_version": [1, 0],
  "policy": {
    "enabled": false,
    "action_dir": "",
    "workspace_dir": "",
    "allowed_commands": ["pwd", "date", "uname", "whoami"],
    "forbidden_paths": []
  },
  "judge": null
}
```

Judge configuration has redacted Debug, travels only in SDK config, and is
rejected as unavailable rather than accepted without a functioning engine.
Invalid thresholds/timeouts are rejected before capability admission.
`PolicyInfo` never returns credentials. The wire version is separate from
release version. Hosts require matching major and module minor >= host minor;
unknown security input fields and enum tags reject rather than authorize.
SDK configuration states the host's required version: initialization and reinit
reject a required minor newer than this module supports, preserving the old
configuration and generation on rejected reinit.

## Trust and supported behavior

Caller agent, thread, flow, call ID, origin and access tier are verified host
facts. Only trusted host adapters may construct checks; model arguments never
supply authority. The original arguments travel as JSON text, keeping the
contract free of serde_json as a normal dependency. Supported bootstrap tool
identities are `local_diagnostic`, `path_check`, and `command_check`, each
requiring matching nonempty checks. Unknown tools deny even with claimed safe
checks. Check is an internal trusted-host operation, not a model-visible tool.

Path checks resolve existing ancestors, including symlinks, and enforce the
credential/system/traversal floor on lexical and resolved forms even when
policy is disabled. Unknown native path dialects, broken symlinks and failed
resolution deny. Enabled action roots must resolve to existing directories;
workspace and configured forbidden roots deny before approval. New files can
be checked through their existing parent. Permission does not guarantee
confinement against a later concurrent filesystem mutation; execution must
retain its own safe-open/jail boundary. Full Windows alias/ADS/device handling
and rich shell grammar parity remain T2. Bootstrap commands allow only exact,
argument-free `pwd`, `date`, `uname`, `whoami` through a trusted host executable
search path. Compound commands, expansions, heredocs, arguments, executable
paths and unrecognized commands deny conservatively on every OS.

Enabled writes deny with `approval_unavailable`; no unusable request IDs are
minted. Unknown tools/effects deny. Cron writes deny even with disabled policy.
Readonly callers cannot write. Decisions include generation and are uncached.
The host must reject stale generations and never retry/fallback after module
faults/timeouts. SDK faults remain latched; ordinary denials do not fault.

## Reserved capabilities

Approval lifecycle/flow/reply, redaction/scanning, privacy/URL guard, sandbox,
audit and host callbacks have typed versioned wire payloads and golden
fixtures. Their engines are not implemented and their member names are not
advertised. No network/DNS pinning, sandbox isolation, audit persistence,
approval expiry, judge verdict or keyring capability is claimed at bootstrap.
Unsupported member calls return the bus's unknown-member error.

## Packaging and smoke checks

CI builds/tests on Linux, macOS and Windows, checks the host contract dependency
tree and enforces per-file coverage. The release workflow retains eleven
native platform keys and produces platform archives, modules.toml and
checksum.toml. No artifact/digest is treated as production-published merely
because a local library builds.

```sh
cargo run -p tinysecurity-module --example verify_module -- <native-library>
cargo run -p tinysecurity-module --example verify_module -- <release-tag-url> <archive> <sha256>
```

The same verifier is used for local and downloaded release artifacts. Local
verification also rejects a wrong digest and tampered bytes before activation,
rejects missing SDK configuration, and confirms stopped modules refuse reinit.
Fault-injection and timeout latching remain SDK conformance work, not a
bootstrap claim. Timing
uses 500 sequential calls per method, one Evaluate call for one diagnostic or
one Check call for two checks per sample. See measured results and migration
budgets in [performance](docs/performance.md).
