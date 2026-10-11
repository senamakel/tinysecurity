# Internal native handle registry

This owner library retains loaded masters, already-derived password keys and
exact plaintext behind typed process-local opaque handles. It composes the
existing material owners and shared WorkBudget admission accounting. It starts
no derivation workers, accesses no credential backend and exports no key or
plaintext read member. Hosts link the minimal TinySecurity bus contract; they
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
This port grants neither native master loading/minting nor renewal. Real
PendingRegistry/NativeConsumer transport and one-time delivery are later scopes.

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

This checkpoint is internal retention and trust-boundary validation only.
It proves neither real native consent/backend access nor confidential bus
dispatch, Argon worker accounting, host RPC adoption, provider selection,
released artifacts or native three-platform operation.

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
