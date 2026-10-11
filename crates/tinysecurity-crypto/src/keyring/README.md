# Injected master resolution

The target, known ordered source inventory, and historical slots are bound by
trusted construction. Existing valid target bytes win. With an absent target,
every registered source must be readable and valid or confirmed absent.
Conflicting decoded masters block resolution. Only absence of all registered
sources permits entropy generation.

A legacy master is copied using its exact original bytes, including hex case,
then compared against target readback before its native key is returned. The
source remains unchanged on success and failure. The generic SecretStore port
does not establish durability, conditional create, or cross-provider CAS.
Therefore readback never authorizes deletion. File import receipts and native
keyring selection are separate future integration work.

A reservation rejects simultaneous resolutions on this resolver. Cancellation
before a set attempt releases it. Once a set is attempted, cancellation, panic,
set failure or failed readback permanently latches this resolver unavailable.
Only a successful set followed by exact target readback releases the reservation.
Before restarting resolution, the owner must independently establish that all
old backend mutations are quiescent; constructing a new resolver does not
establish this. This library provides no recovery or automatic retry mechanism.

There are no awaits under state locks. Construction must have one boot owner per
target: separate resolvers and other processes are not serialized by this
library. Driver native key-creation locks do not establish cross-provider
migration atomicity.

The app:master_key, {user}:secretstore.master_key, and .secret_key slots remain
distinct. This checkpoint binds target and all registered sources to one slot.
Explicit source-slot registration for legacy .secret_key-to-user migration remains
pending; no filesystem I/O or cross-slot fallback is implemented.

No method is advertised through TinyBus at this checkpoint. Native keyring
providers, durable consent callbacks, handles and real three-OS acceptance
remain pending. MemorySecrets tests prove injected policy, not OS capability.
