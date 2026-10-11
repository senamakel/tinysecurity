//! Inventory regression against the hash-admitted, genuinely loaded artifact.
use std::collections::BTreeSet;
use tinybus::{Proxy, module::manifest::ModuleManifest, version::InterfaceVersion};
use tinysecurity_bus::{PolicyInfo, callback_names2, names};

pub(super) async fn verify(
    manifest: &ModuleManifest,
    proxy: &Proxy,
) -> Result<(), Box<dyn std::error::Error>> {
    let policy: PolicyInfo = proxy.call(names::methods::POLICY_INFO, ()).await?;
    let provided = manifest
        .provided(&names::INTERFACE.parse()?)
        .ok_or("loaded artifact omits policy interface")?;
    let methods: BTreeSet<_> = provided
        .methods
        .iter()
        .map(tinybus::MemberName::as_str)
        .collect();
    let canonical: BTreeSet<_> = names::METHODS.iter().copied().collect();
    let runtime: BTreeSet<_> = policy.capabilities.iter().map(String::as_str).collect();
    assert_eq!(
        methods, canonical,
        "loaded artifact must advertise every implemented permission method"
    );
    assert_eq!(
        methods.len(),
        provided.methods.len(),
        "no duplicate methods"
    );
    assert_eq!(
        methods, runtime,
        "manifest must agree with actual PolicyInfo"
    );
    assert_eq!(manifest.provides.len(), 1, "only policy is implemented");
    assert_eq!(
        manifest.requires.len(),
        1,
        "only implemented audit forwarding may be advertised"
    );
    let audit = &manifest.requires[0];
    assert!(audit.optional, "native/absent audit needs no host callback");
    assert_eq!(
        audit.interface,
        InterfaceVersion::consumed(
            callback_names2::AUDIT_SINK.parse()?,
            manifest.module.version.clone()
        ),
        "AuditSink2 must use the SDK package-version and caret minimum"
    );
    Ok(())
}
