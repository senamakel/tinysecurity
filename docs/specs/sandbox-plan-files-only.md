# Sandbox Plan: files-only jails

`SandboxPlanOptions2.files_only` lets the operator's own command run under a jail
that confines only the filesystem, on the host's network. It exists for Linux
Landlock where nothing stronger can start: inside a container that blocks user
namespaces, bubblewrap fails and Docker is absent, while Landlock still restricts
every path the command can reach.

## Why an option

`Plan2` requires every plan to enforce the filesystem and the network. Landlock
declares only the filesystem as enforced and no process isolation, so it never
qualifies, and a sandboxed shell in such a container is refused `unsupported`.
A shell already granted the host's network (`NetworkPolicy::Host` under the
scope's `operator_host_network`) gains nothing from a network rule, yet the
requirement still excludes the one jail that would confine its files.

Dropping the requirement for every host-network request would silently move
every such agent onto a weaker jail. The option keeps that decision explicit
and per request: a host asks for it only for an agent its operator opted in.

## Behaviour

With `files_only` set:

- A request for `NetworkPolicy::Host` requires only the filesystem (plus any
  requested resource or subprocess bounds). A request for any other network
  policy keeps the network requirement.
- On the trusted-folder pass (`accept_process_isolation`), an executor with no
  process isolation qualifies when it enforces the filesystem exactly. A
  best-effort filesystem never qualifies without isolation.
- A kernel executor that meets the floor with every requirement enforced is
  still preferred.
- The artifact states `minimum_isolation: process` and lists only the
  filesystem constraint. It never claims kernel isolation.

It is refused (`floor`) when the request does not set
`accept_process_isolation`, when the source is not `trusted_host`, and when
the deployment or origin is `SaaS` or unlabelled. `ConsumeSandboxPlan2` and
`validate` re-derive the plan from the request, so a files-only artifact
cannot be reused by a request that does not set the option.

## Compatibility

The field defaults to off and is absent from the wire when off, so existing
hosts and their fingerprints are unchanged. A module older than this field
rejects a request that sets it (`deny_unknown_fields`), so a host that asks for
a files-only jail fails closed against an older module.
