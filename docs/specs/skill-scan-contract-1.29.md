# Host skill-scan decisions (contract 1.29)

`Check::SkillScan` carries the trusted host's `Pass`, `Warn`, or `Block` result
for the exact installed skill bundle an agent is about to execute. The request
also carries a lowercase SHA-256 digest over the document and every resource
the run can expose. TinySecurity binds that digest into the approval request;
it does not read skill files or trust a verdict supplied by a model or caller.

The host must derive the verdict from its scanner over the same bytes the run
will consume. It must preserve that snapshot for the run, or verify the digest
again before exposing any resource. A changed bundle requires a fresh scan and
policy evaluation. The digest is an approval binding, not a content signature
or a substitute for the host's authenticated bus adapter.

Policy maps the verdicts as follows:

- `Pass` succeeds this check; all other policy checks still apply.
- `Warn` returns `ApprovalUnavailable`, which the host maps to its existing
  human-approval path. It never silently becomes an allow.
- `Block` returns `DenialReason::Content`, a hard refusal that approval cannot
  override.
- A malformed digest returns `DenialReason::InvalidContext`.

The check is not reusable by registered-policy decision caching. Its verdict
and bundle digest remain in the canonical call fingerprint and approval
binding, so a changed document cannot reuse the earlier warning decision.
