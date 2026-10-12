# Native App store implementation order

Accepted constraints: [specification](../specs/native-app-store.md).

1. Pin the merged driver transaction API without copying its implementation.
2. Reproduce physical transition admission failure; add a shared gate and gated
   clock/state validation, preserving gate-before-state lock order.
3. Add private App operation/master/resource bindings and charge reservations.
   Exclude generic master and routine authorization.
4. Consume typed approval proof against an independently generated safe wrapper.
   Capture fixed audit and confidential consumer ports.
5. Add one finite dedicated worker and retained physical job cancellation.
   Bind driver phases to live authority; fence uncertain mutations.
6. Test lifecycle/publication ordering, cancellation, bounds, substitution, ordinary
   driver compatibility and final audit failure with deterministic synchronization.
7. Run modern/MSRV contract checks and native fixture/coverage proofs; publish
   this internal slice only after source and proof review. Module composition and
   provider provenance remain separate work.
