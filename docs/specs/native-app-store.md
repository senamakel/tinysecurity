# Internal native App store

The crypto owner captures one driver-owned exact private file resource and fixed
consumer at trusted initialization. Initialization neither resolves a master nor
grants file access. Get, Set and Delete require an existing live App master,
operation-specific consumed typed Human Once consent and required native audit.
Config cipher purpose remains separate. This slice introduces no bus operation,
provider provenance, Host cutover, List, recovery, import or document storage.

Admission binds authenticated peer, original subject, exact resource, name,
operation/input, selected master identity/epoch, generation, both clock deadlines
and fixed consumer in a private keyed commitment. Requests and key copies remain
charged through actual physical worker completion and confidential output wiping.
One dedicated worker uses a finite queue; full admission rejects without waiting.
Exact encoded/context lengths are checked before owner-created confidential copies.
Aggregate admission includes original input capacities, bounded encoded backing,
challenge, driver scratch, copied key and output. Independent initialization ceilings
are finite; full driver map/ciphertext admission remains the driver's responsibility.

A shared physical authority gate precedes registry state locking and every clock sample. Driver leases
retain the gate through physical publication, flush and exact readback. Close,
revocation, generation activation and clock invalidation wait for that lease;
they do not interrupt or undo an already executing OS operation. Cancellation
and expiry deny normal acknowledgment even if bytes became visible.

Intent and execution audit precede enqueue. Final actual audit precedes output
delivery and publication. Uncertain mutations and failed final audit permanently
fence the owner. Generation change, another resource or initialization cannot
clear that uncertainty in the live registry. An ordinary worker unwind immediately
fences the registry after physical leases unwind, wipes current/queued backing and
denies/wakes retained waiters without resuming the resource. Caught run/notification
payloads remain retained until that owned cleanup and queue completion finish.
A fixed 33-slot collection covers the registry's maximum 32 admitted jobs plus
one run fault. Receiver teardown disconnects before dropping queued jobs. Primary
payloads each receive one guarded disposal attempt; secondary destructor-panic
payloads are conservatively retained without recursion. This finite fault count
does not bound opaque foreign bytes, wipe foreign copies, guarantee blocking
destructor quiescence or recover abort execution. Retained owner reservations
stay charged until actual backing Drop. No global panic hook
is replaced. Abort, foreign exceptions, FFI escape and process death remain outside
this in-process fence; it is not durable crash recovery. Get plaintext reaches only the fixed
bounded native consumer after final audit and a live check.

See [implementation order](../plans/native-app-store.md).
