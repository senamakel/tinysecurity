# Native credential roots

Contract 1.24 adds `CredentialRoots2` for a host that must pass unconditional
credential-store denials to a separate jail or grant resolver. The host supplies
its trusted operator home as `CredentialRootsRequest2.home`; `None` returns an
empty list and preserves home-less isolation. The member does not discover a
home from process environment variables.

The native policy builds candidates from the same credential-store vocabulary
as the lexical floor. It covers the home-level SSH, GnuPG, AWS, Azure and kube
directories; single-file stores; Docker and Cargo credential files; macOS
`Library/Keychains`; and Windows `AppData` Microsoft Credentials, Protect, Crypto,
Vault and Ngc stores. Windows roots include both Roaming and Local containers
where the platform uses them.

For each candidate, the response includes its lexical path and the canonical
path. Existing symlinks therefore contribute both the supplied alias and its
target. A missing store is resolved through its nearest existing ancestor and
retains the missing suffix, which also protects stores created after planning.
An invalid home, dangling symlink, non-`NotFound` filesystem error, or a result
that exceeds the 64-root and 4096-byte bounds fails closed. Paths are never
included in `Debug` output.

The result is a finite set of anchored native locations for a host's jail
configuration. Individual path checks continue to use the lexical floor, which
matches credential names at arbitrary depth. A host must pass the module's
result through unchanged and must not replace it with a locally maintained
credential list.
