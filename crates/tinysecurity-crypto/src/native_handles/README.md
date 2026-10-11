# Internal native handle registry

This owner library retains loaded masters, already-derived password keys and
exact plaintext behind typed process-local opaque handles. It composes the
existing material owners and shared WorkBudget admission accounting. It starts
no derivation workers, accesses no credential backend and exports no key or
registry plaintext read member. Its typed config cipher owner runs bounded
SecretCipher primitives synchronously and offers confidential output only to
a fixed trusted native delivery port. Hosts link the minimal TinySecurity bus contract; they
must not link this implementation library.

Registry initialization captures trusted subject registrations, purposes,
policy references and the actual authenticated SDK peer. Registrations are
ceilings, not live consent. A trusted handler reserves an exact memory-only
operation, captured generation, original call and bounded lifetime. Each
reservation owns a fresh private challenge. A separately sampled private
generation key authenticates a versioned, domain-separated, length-prefixed
HMAC stream including the original input and every authority binding. Only
the keyed commitment's safe argument wrapper and call correlation may enter
durable approval or audit data. Do not append a raw input hash, password,
plaintext, challenge, handle or generation authorization key.

Native masters require HumanGrantVerifier. Its implementation MUST finish
actual authenticated VerifyHuman, exact Human Once decision and consumption
CAS, and required ordered durable audit before acknowledging. A Reserved row,
matching nonce, audit-shaped object or calling the receipt constructor is not
independent proof that any backend operation occurred. This trusted Rust port
is the integration provenance boundary. The registry additionally checks
exact keyed echo, private challenge, purpose, registered durable subject and
policy, generation, safe original call/arguments, nonce, reservation winner,
ticket correlation, Once choice and exact audit event/tail. Proof expiry must
equal the reserved deadline. Reusable, automatic/judge, prepared, incomplete
or substituted evidence cannot issue a publication token. Integration must
derive approvals' outer content hashes solely from the safe argument wrapper.

Caller-owned password keys and plaintext instead require NativeRoutineVerifier.
That trusted port MUST consume a live private pending authorization for the
actual authenticated handler, exact original operation/input, registered
purpose, fresh private challenge, output class and consumer. Pending identity
strings and constructing a receipt do not create provenance. The pending owner
must bind the reserved deadline or shorten the reservation before admission.
This port grants neither native master loading/minting nor renewal. The typed config cipher consumer below has its own real private pending owner;
these external retention receipts cannot authorize config cipher work. Actual
authenticated bus consumer transport remains a later scope.

Both verifier futures run outside the registry mutex. Live registry identity,
generation, epoch, clocks, commitment and expiry are checked before and after
the callback, and again at publication. Publication tokens are move-only and
consumed once. Existing-device authority is unchanged. Unrelated registrations
retain their own rates and epochs. Revocation wipes that registration's entries;
generation advance rotates the private authorization key and wipes all entries.
Clock rollback or clock-port failure permanently closes authority. Close works
even when retained objects or pending futures still own the registry.

Bounds cover registrations, handles, admitted operations, per-subject rate,
per-input logical bytes, pending input backing capacity/challenge bytes,
retained native backing capacity and
combined pending/retained/generation-key bytes. At most 4096 handles, 32 admitted
operations, one MiB per input and 300000 ms lifetime are admitted. Password
retention input bindings are at most 4112 bytes (password plus fixed salt);
this is not a password parser or a derivation worker. Retained and pending
ceilings are at most sixteen MiB each, combined ceiling thirty-two MiB.
Input and plaintext Vec capacities are charged in full, even when their logical
length is smaller. Admission never shrinks or reallocates these secret buffers
to conceal their backing capacity. Fixed master/password keys, challenges and
the generation key each contribute 32 bytes. Logical input ceilings remain
separate from these backing-capacity limits.
No wait queue exists. Cancellation releases capacity without refunding rate;
old-generation reservations keep their private-input charges until actual Drop.
These counters measure registry-owned secret buffers, not the complete allocator,
trusted callback's receipt allocations, caller's external material or SDK frames.

Owned input, challenge, handle, authorization-key and plaintext buffers use
fixed existing allocations with zeroizing ownership. Deterministic tests inspect
live wiped slices immediately before their allocation is released. Existing
master/password owners retain their existing cleanup contracts. No claim is
made about perfect stack/register cleanup, external caller copies, serde/SDK
frames or process-wide memory erasure. The API has no serde authority types.

This checkpoint provides internal retention, typed config cipher execution and
trusted native-port delivery validation. It proves neither real native
consent/backend access nor confidential bus dispatch, Argon worker accounting,
host RPC adoption, provider selection, released artifacts or native
three-platform operation.

The approval owner exposes trusted native begin/consume prerequisites with a fixed
owner-sampled deadline and the exact keyed native call correlation. Its reserved
label is rejected by generic execution paths. Native provenance is bounded to 32
live intents and exists only in the same Engine instance; serialized rows cannot
reconstruct it after restart or reinitialization. Actual Human verification and
acknowledged decision/consumption CAS establish private state snapshots.
Every native phase requires a confidential required-sink acknowledgement; an
unimplemented native audit port denies before prompting. The acknowledgement
retains the actual sink response and independently captured sanitized audit scope,
which differs from the approval subject digest. Trusted constructors validate
shape and binding, while the captured adapter remains responsible for provenance.
Borrowed reservation bindings retain their original deadline, and live grant
validation must bracket every subsequent backend await. Injected linked SDK tests
exercise this composition; they do not establish real OS consent or storage.

`Reservation::validate` rechecks the original admitted work before a module returns
a cached pending review. It preserves the same challenge and deadline and fences
rollback, expiry, scope revocation and generation changes through the owner registry.


## Typed config cipher consumer

`cipher::CipherOwner::new` captures the existing registry, immutable trusted
`CipherConfig` (encryption setting and fixed consumer registration), and one
`NativeCipherConsumer`. These values must come from trusted native
initialization, never from an invocation's claims or arbitrary callback. Only
`ConfigUserMaster` is supported here; App encrypted-map/document and password
consumers remain distinct capabilities.

`prepare(CipherRequest)` validates the actual captured peer and selected
`MasterHandle`, then reserves the original input and creates a move-only
`CipherPending`. The original private HMAC includes `CipherKind` (encrypt,
decrypt, migrate), master identity/epoch/expiry, fixed destination, trusted
encryption setting and private owner identity, in addition to the existing
subject/registration/policy/call/generation/challenge fields. Its deadline
cannot exceed either clock's master deadline. The bounded private pending
table consumes the exact operation once; dropping pending cancels it.
External `NativeRoutineVerifier` receipt constructors and public retention
reservations cannot manufacture this cipher authority.

`execute` consumes that private pending entry and runs `SecretCipher` under
the registry lock with no await, spawned worker or second queue. The registry
never returns or lends master bytes to an external callback. It validates live
master and reservation state before native work, before delivery, after the
consumer future and immediately before the final result. Revocation,
generation changes, expiry and permanent clock faults deny publication.

True nonempty enabled encryption returns an enc2 ciphertext. Decrypt,
plaintext, disabled encryption and empty passthrough instead reach only the
fixed `NativeCipherConsumer::deliver` future as a borrowed `CipherDelivery`.
Legacy migration binds plaintext and the exact replacement together. Enabled
migration can return its true encrypted replacement after acknowledgement;
disabled migration keeps the plaintext replacement inside confidential
delivery. `CipherDelivery::acknowledge` returns a move-only private receipt
binding original operation and exact keyed output. Calling it acknowledges
actual delivery at the trusted port; its shape alone cannot prove transport
provenance. Debug, errors and safe arguments never contain plaintext or keys.

The consumer must perform all delivery inside its future without detached
work and acknowledge only completion at its fixed authenticated destination.
The original reservation, input and zeroizing outputs remain owned through
that future's completion or actual cancellation/drop. Tests prove this
in-process contract; dropping a future is not evidence that a bus receiver,
OS call or detached worker stopped. A future native transport needs a physical
slot/completion owner or bounded uncertainty fence, plus staging and final
commit/abort acknowledgement, before releasing product-controller plaintext
or claiming real transport quiescence. This library does not implement that
transport or product publication handshake. Delivery exposes the immutable
registration and original subject to this trusted port plus `safe_call_id`,
the private keyed original-operation correlation, which distinguishes repeated
original call IDs without exposing raw input or an unkeyed input hash. The
adapter must compare this scope against its independently captured native
destination, rather than using caller identity strings.

Plaintext remains bounded to one MiB. Encoded cipher inputs have separate
bounds including historical prefix, nonce and tag: at most 2,097,213 bytes for
enc2 and 2,097,156 for legacy enc. Smaller configured plaintext limits produce
correspondingly smaller envelopes. No global retention/input ceiling grows.
Original input backing capacity is charged unchanged; preparation additionally
charges conservative simultaneous primitive scratch, master-copy and output
capacity before native work. Output capacity is checked against that charge;
confidential buffers are never shrunk to hide their allocation. Consequently
valid large inputs can require larger configured pending/resident budgets.
Invalidating a generation does not release the original owner's charge before
actual Drop. No cancellation refunds the per-registration rate.

Owned plaintext and replacement strings use zeroizing allocations and wipe
live slices before release; tests inspect this boundary on delivery failure,
cancellation and late acknowledgements. Existing driver primitive cleanup,
caller/native-consumer copies, stack/register temporaries and process abort
retain their documented limits. The complete format fixtures, tampering,
nonce freshness, private binding substitutions, exact once consumption and
full envelope boundary are covered in `cipher_tests.rs`.

The 1.11 module adapter uses `CipherPending::binding`/`matches_input` and
`CipherOwner::validate_pending` for exact read-only audit/input checks.
`execute_guarded` produces a move-only `CipherCompletion` retaining the original
Reservation and classified output through the caller's final required audit.
Its `validate` brackets final awaits and `publish` performs the final selected
master/epoch/generation/deadline check before returning a safe result. Dropping
or canceling this guard releases admission without refunding rate. No new
receipt constructor or raw master accessor is added. `CipherDelivery` exposes
only keyed exact-output correlation in addition to its existing trusted port
metadata. This supersedes the earlier immediate-completion API's narrower
final-audit lifetime; `execute` remains a immediate-publication convenience.
