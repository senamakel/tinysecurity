# TinySecurity implementation sequence

- Status: T0/T1 bootstrap in progress; remaining tasks not implemented
- Specification: [accepted behavior](../specs/security-module.md)
- Trackers: [TinySecurity #1](https://github.com/tinyhumansai/tinysecurity/issues/1),
  [OpenHuman #7328](https://github.com/tinyhumansai/openhuman/issues/7328),
  [TinyBox #27](https://github.com/tinyhumansai/tinybox/issues/27)

## Delivery and validation rules

Use one cumulative PR per affected repository. Task numbers mark dependency
order, not separate PRs. Preserve all checkpoint commits. Open PRs against
canonical upstreams. A PR description distinguishes implemented capabilities
from the remaining tracker; this bootstrap does not close either tracker.

For every behavior: add the failing test, run it against existing code, implement
the smallest complete behavior, rerun it, then run the owning crate suite.
Port host characterization tests before deleting the implementation they pin.
Use sibling `*_tests.rs` modules and deterministic time/filesystem/resolver seams.
No stub engines, blanket lint allowances or ignored failures.

At each completed task run from the root:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo build --all-targets --all-features
cargo test --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
```

Run dependency/license, MSRV, per-file coverage and native matrix checks as they
are introduced. Record actual outcomes. Worktrees retain build output under
the checkout/shared configured target; never export `CARGO_TARGET_DIR`.

## T0 — Replace the template with a useful native module

**Files:** root `Cargo.toml`, `Cargo.lock`, `AGENTS.md`, `README.md`, `MODULE.md`,
`ROADMAP.md`, `SECURITY.md`, `.github/workflows/{ci,release}.yml`,
`crates/tinysecurity-bus/`, `crates/tinysecurity-policy/`,
`crates/tinysecurity/`, `crates/tinysecurity-module/`, and these design documents.

1. Pin the existing TinyBus submodule. Inspect its init/reinit, ABI exports and
   call dispatch; reuse its SDK rather than inventing RPC lifecycle members.
2. Rename template-bus to tinysecurity-bus and template to tinysecurity-module.
   Implement policy in tinysecurity-policy, with a tinysecurity internal umbrella
   re-exporting that engine and tinysecurity-module owning only SDK/ABI dispatch.
   Each crate has a concrete role; create further engines when they contain
   behavior. Set canonical repository metadata and security contact.
3. Delete greeting types, handlers and examples. Replace them with an example
   that loads the native module and proves one allow plus one floor denial.
4. Write integration tests asserting interface/object names, advertised
   Evaluate/Check/PolicyInfo members and absence of unimplemented handlers.
5. Implement the minimal deterministic policy: safe read versus external
   effect, credential/path floor, conservative unknown command handling,
   configuration validation and generation. Bootstrap denies any effect it
   cannot fully authorize; it does not create nonfunctional approvals.
6. Test malformed args, missing config, denied effects, accepted/rejected reinit
   and ordered Check batches through the real TinyBus module loader.
7. Update CI/release crate names and build the module on supported native runners.
   Verify package manifests and checksum production, not just Rust compilation.

**Exit:** no template/greeting behavior; useful policy calls through a native
module, accurate bootstrap docs and all root checks green.

## T1 — Publish the versioned contract and golden fixtures

**Files:** `crates/tinysecurity-bus/src/{names,version,error,policy,approval,
redact,egress,sandbox,audit,callbacks}/`, `src/lib.rs`,
`crates/tinysecurity-bus/tests/`, `tests/fixtures/`, `MODULE.md`.

1. Add failing serde golden tests and round trips for PolicyConfig, verified
   CallerContext, ToolCall, Decision, batched Check, PolicyInfo and generation.
   Use `#[non_exhaustive]` where source evolution is expected; define strict
   wire version compatibility rather than relying on that annotation.
2. Define SDK init/reinit configuration separately from invocation args. Secrets
   have explicit redacted Debug. Test that formatted config never contains the
   fixture credential. Reject invalid thresholds/TTLs/config before activation.
3. Define typed future contracts/constants for Decide, ListPending,
   ListDecisions, RecordExecution, PreauthorizeFlow, ParseReply; Redact,
   ScanPrompt, ScanToolDefinition, EgressCheck, UrlGuard; Plan; Audit; and
   ApprovalStore, ApprovalPrompt, AuditSink, KeyringConsent callbacks. Pin every
   public payload and error with fixtures. Do not advertise unimplemented members.
4. Specify caller-verified context, policy generations, conservative cache
   eligibility and callback failure semantics. Omit an unenforced cost-cap field.
5. Assert normal dependencies are serde+thiserror only with `cargo metadata`
   and the CI contract-dependency check. Golden serialization uses dev deps.
6. Verify incompatible version rejection, unknown enum/field behavior and
   transport-free compilation. Test all exported error variants.

**Exit:** complete typed contract is available; only implemented capabilities
are callable. SDK config and wire fixtures agree with actual native behavior.

## T2 — Full policy engine and characterization parity

**Files:** `crates/tinysecurity-policy/src/{rules,command,path,rate}/`, module
policy adapter; host `tests/security_policy_characterization.rs` and its explicit
`crates/openhuman-cli/Cargo.toml` test entry.

1. Characterize OpenHuman disabled/enabled autonomy, always-forbidden floor,
   action/trusted roots, unknown command writes, tool rules and rate exhaustion.
2. Port classification/scanning from host security and TinyBox shell policy
   into the owning policy engine. Reuse the single TinyTools type copy.
3. Test POSIX substitutions, quoted heredoc data versus unquoted expansion,
   PowerShell/cmd escaping, executable resolution and compound commands.
4. Implement native path normalization and symlink-aware checks. Test APFS
   aliases/case, Windows drive/UNC/device/ADS/reserved/short names, traversal
   and NUL, trusted-root intersection and protected credential roots.
5. Add deterministic rate reservation/accounting tests; no generation cache
   bypass. Migrate the unused host daily-cost setting out of config with tests.
6. Run policy parity tests across all three OSes. Do not migrate host callers
   before T9 release and latency gates.

## T3 — Unified redaction and scanning

**Files:** `crates/tinysecurity-redact/src/{patterns,structured,prompt}/`, shared
redaction fixtures; module Redact/ScanPrompt/ScanToolDefinition adapters.

1. Capture every host redactor's results over one secret/PII/path/URL corpus.
2. Add failing corpus tests for each mode, escaped JSON, nested args, URL userinfo,
   home paths and malformed inputs; preserve useful nonsecret diagnostics.
3. Implement one bounded pattern registry and structured key rules. Define
   scanning ownership with TinyMCP/TinySkills before importing duplicated logic.
4. Add idempotence and bounded-work properties plus fuzz cases. Test all output
   destined for judge/storage/events, including callback errors, is sanitized.
5. Admit bus handlers only after complete tests. Document unavailable-module
   logging suppression/floor so no early boot secret leaks are introduced.

## T4 — Privacy, URL guards and actual egress enforcement

**Files:** `crates/tinysecurity-egress/src/{privacy,url,resolver}/`, module
egress adapters; owning host/browser HTTP transport connection seams.

1. Test literal metadata, CGNAT, IPv6 local/mapped/zone forms, unusual IPv4 forms,
   domain allowlists and mixed public/private DNS answers with a fake resolver.
2. Define distinct Sensitive behavior with descriptor tests or remove it through
   host migration. Test LocalOnly denial for every actual egress entry point.
3. Implement resolution and validation of every candidate address. Build the
   real transport seam that connects to approved IPs and retains TLS host checks.
4. Stub a resolver whose second answer becomes private; prove the transport
   does not resolve again or dial the changed answer. Recheck and pin redirects.
   Exercise browser/proxy connectors; require mediation or deny if no seam exists.
5. Audit protected connections on Linux/macOS/Windows. Never describe URL-only
   tests as proof of DNS rebinding protection.

## T5 — Sandbox planning and TinyBox execution contract

**Files:** `crates/tinysecurity-sandbox/src/{plan,capabilities}/`, module Plan
adapter; TinyBox upstream contracts/backends; host sandbox translation.

1. Add tests for SaaS/env/agent/config precedence, untrusted sources, network
   grants, protected paths, resource limits and unsupported capabilities.
2. Implement deterministic plans; keep all launch code in TinyBox. Namespace,
   microVM, jail and Docker choices require actual reported capabilities.
3. Work TinyBox #27 upstream: suitability/Noop refusal, plan execution and
   backend resource/network enforcement. Remove unsupported host config fields
   with migrations instead of silently accepting them.
4. Inventory cron, MCP stdio, runtime pools, hooks, workflows, installers and
   agent/browser helper processes. Route each untrusted spawner through TinyBox
   and document its source trust, placement and cross-OS tests.
5. Confirm SaaS off override denial and floor grants on native runners. TinyBox
   release precedes OpenHuman execution migration.

## T6 — Audit with confirmed persistence

**Files:** `crates/tinysecurity-audit/src/{events,sink,rotation}/`, AuditSink
callback client and module Audit handlers.

1. Test sanitized policy, approval, execution, sandbox and judge rows, ordering,
   rotation limits, permission restrictions and sink errors.
2. Implement one event model and explicit required-audit failure behavior.
   Confirm persistence before acknowledging a committed row.
3. Test Unix 0600 and Windows ACL/locking/long-path rotation behavior. Decide
   TinyMCP audit ownership and use a facade rather than a second engine.

## T7 — Durable approval lifecycle

**Files:** `crates/tinysecurity-approval/src/{state,store,reply,flow}/`, callback
contracts/client and module approval handlers; host storage/prompt server.

1. Characterize host RPCs and gate short circuits, ten-/three-minute TTL,
   restart survival, deny, once/tool/flow trust, preauthorization and cron.
2. Add fake-clock/storage callback tests for pending→decided/expired→executed,
   duplicate decisions, replay, caller/fingerprint mismatch and unavailable store.
3. Implement the state machine; keep future parking and UX host-side. Bind
   grants to verified context and preserve existing RPC/event wire shapes.
4. Redact all persisted/broadcast data. Audit auto_approve_all and execution
   outcomes. Test SaaS configured prompt channel and denial when absent.
5. Exercise native callback round trips, expiry and restart on all three OSes.

## T8 — Optional Jev judge

**Files:** `crates/tinysecurity-auto/src/{rules,judge,budget}/`, module config;
local stub judge integration tests; host approval log presentation.

1. Test Deny/floor immutability, per-origin opt-in, redacted input and safe
   credential Debug/init boundaries before adding any HTTP client.
2. Integrate TinyInference Decisions inside the module. Implement independent
   intent/reversibility/exfiltration questions and explicit local thresholds.
3. Stub allow, deny, low confidence, malformed output, HTTP failure, timeout
   and unavailable service; every uncertain result retains human approval.
4. Test request budgets and any cache against changed caller/call/mutable
   authorization state. Audit sanitized questions/scores/thresholds/auto:jev.
5. Add host UI verdict presentation and translated strings only after release.
   Never treat the inference client's score as permission by itself.

## T9 — Complete native adapter, latency and upstream release

**Files:** `crates/tinysecurity-module/`, `.github/workflows/`, release packaging,
native conformance tests,
`benches/`, `MODULE.md`.

1. Implement every finished engine's ABI dispatch and host callbacks with
   typed failures, bounded calls, config activation and fault latching.
2. Test incompatible versions/digests, tampering, missing/faulted/timed-out
   modules and no in-process retry. Reinit cannot reset the fault latch.
3. Benchmark p50/p99 Evaluate/Check and calls per representative turn against
   host characterization. Agree and commit budgets before moving callers.
4. Validate all eleven release host keys, package names, immutable archives
   and checksum manifest. Run published-archive loader smoke tests for allow,
   floor deny, config changes and callbacks on supported native runners.
5. Merge/release upstream capabilities before host caller migration. A local
   artifact may prove tests but may never supply a production registry digest.

## T10 — Reviewed policy changes

**Files:** `crates/tinysecurity-policy/src/{schema,diff,activation}/`, module
policy generation adapter and host policy review UI.

1. Test versioned declarative policy validation and diffs that expand path,
   host, tool, class, auto-approve origin or judge reach.
2. Require verified human review before activating expanded reach. Reject
   unreviewed changes; preserve old generation after failed config/review.
3. Emit PolicyChanged only after accepted activation. Test host stale-result
   rejection and static-cache invalidation during concurrent policy changes.

## T11 — Crypto, keyring and pairing last

**Files:** `crates/tinysecurity-crypto/src/{password,keyring,device,pairing}/`,
KeyringConsent callback and module crypto adapters; host consent/socket UX.

1. Capture legacy Argon2/AES-GCM and device X25519/HKDF test vectors; test old
   encrypted data compatibility, wrong passwords and tampered ciphertext.
2. Consolidate implementations without moving auth/credential ownership.
   Test secret handling, consent refusal/unavailability and pairing expiry.
3. Run native Secret Service/file, Keychain and Credential Manager tests with
   controlled credentials; document OS capability gaps explicitly.
4. Release upstream before host encryption/keyring/device implementation removal.

## OpenHuman integration and final verification

Within its single cumulative PR, first add characterization tests, feature-chain
and bus-only manifest checks, then the attested host adapter and callbacks.
After upstream releases, pin gitlinks and copy published checksums. Preserve
approval.*, security.*, sandbox.* and encryption.* RPC names. Consolidate config
through one translator, then migrate callers in tracker order and remove their
old engines/tests only after parity passes. The one security middleware must
use verified context and retain TinyAgents-owned generic behavior upstream.

Run feature on/off builds, layout/chain/pin/forwarding/i18n/docs checks and real
released-module three-OS E2E. Assert a killed module denies effects, all untrusted
spawners refuse Noop, the unified corpus passes and actual network pinning holds.
Update user-facing capability docs and generated architecture markers.

Close the tracker only when these results, releases and final host migrations
exist. Report bootstrap progress and remaining tasks accurately until then.
