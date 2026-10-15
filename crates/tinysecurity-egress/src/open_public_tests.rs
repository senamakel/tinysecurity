use super::*;
use std::{net::IpAddr, time::Duration};
use tinysecurity_bus::{AccessTier, DestinationRule, LocalEgressCapability, PrivacyMode};

#[derive(Debug)]
struct Clock;
impl EgressClock for Clock {
    fn now_ms(&self) -> u64 {
        42
    }
}
#[derive(Debug)]
struct Dns(Vec<IpAddr>);
impl Resolver for Dns {
    fn resolve(
        &self,
        _: &str,
        _: Duration,
        _: usize,
    ) -> std::result::Result<Vec<IpAddr>, crate::ResolveFailure> {
        Ok(self.0.clone())
    }
}
fn owner() -> SubjectScope {
    SubjectScope {
        user: "user".into(),
        workspace: "workspace".into(),
        agent: "agent".into(),
    }
}
fn open_policy() -> EgressPolicy {
    EgressPolicy {
        owner: owner(),
        ceiling: AccessTier::Full,
        privacy: PrivacyMode::Standard,
        destinations: vec![],
        data_categories: vec![DataCategory::UserContent, DataCategory::HostMetadata],
        local_capabilities: vec![],
        validity_ms: 1000,
        open_public: true,
        preflight_transports: vec![],
    }
}
fn request(id: EgressPolicyId, url: &str) -> ScopedEgressRequest {
    ScopedEgressRequest {
        policy_id: id,
        subject: owner(),
        tier: AccessTier::Full,
        url: url.into(),
        method: "GET".into(),
        category: DataCategory::UserContent,
        payload: String::new(),
        headers: vec![],
        transport: EgressTransport::PinnedDirect,
        local_capability: None,
        transformation: None,
    }
}
type R = std::result::Result<(), Box<dyn std::error::Error>>;
fn registry(
    policy: EgressPolicy,
) -> std::result::Result<(EgressPolicyRegistry, EgressPolicyId), Box<dyn std::error::Error>> {
    let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
    let id = registry.register(policy)?;
    Ok((registry, id))
}
fn public() -> Dns {
    Dns(vec![IpAddr::from([93, 184, 216, 34])])
}

#[test]
fn open_public_authorizes_any_public_host_with_pinned_sockets() -> R {
    let (registry, id) = registry(open_policy())?;
    for url in [
        "https://example.org/a",
        "http://news.example.net:8080/x?q=1",
        "https://93.184.216.34/",
    ] {
        let result = registry
            .get_owned(&id)?
            .check(&request(id.clone(), url), 1, &public());
        assert_eq!(result.denial, None, "{url}");
        let auth = result.authorization.ok_or("authorization")?;
        assert_eq!(auth.addresses.len(), 1);
    }
    Ok(())
}
#[test]
fn open_public_still_applies_the_address_floor_to_literals_and_resolved_names() -> R {
    let (registry, id) = registry(open_policy())?;
    let scope = registry.get_owned(&id)?;
    for url in [
        "http://127.0.0.1/",
        "http://169.254.169.254/latest/meta-data",
        "http://10.0.0.5/",
        "http://100.64.0.1/",
        "http://[::1]/",
        "http://[fd00::1]/",
    ] {
        let result = scope.check(&request(id.clone(), url), 1, &public());
        assert_eq!(result.denial, Some(EgressDenial::Address), "{url}");
    }
    for hostile in ["127.0.0.1", "169.254.169.254", "10.1.2.3", "fe80::1"] {
        let dns = Dns(vec![IpAddr::from([93, 184, 216, 34]), hostile.parse()?]);
        let result = scope.check(&request(id.clone(), "https://rebind.example.org/"), 1, &dns);
        assert_eq!(result.denial, Some(EgressDenial::Address), "{hostile}");
    }
    Ok(())
}
#[test]
fn closed_policy_still_refuses_unregistered_destinations() -> R {
    let mut closed = open_policy();
    closed.open_public = false;
    closed.destinations = vec![DestinationRule {
        scheme: "https".into(),
        hostname: "example.com".into(),
        port: 443,
        include_subdomains: false,
    }];
    let (registry, id) = registry(closed)?;
    let result =
        registry
            .get_owned(&id)?
            .check(&request(id.clone(), "https://example.org/"), 1, &public());
    assert_eq!(result.denial, Some(EgressDenial::Destination));
    Ok(())
}
#[test]
fn browser_and_proxy_need_an_explicit_preflight_opt_in() -> R {
    let (strict, strict_id) = registry(open_policy())?;
    let mut browser = request(strict_id.clone(), "https://example.org/");
    browser.transport = EgressTransport::Browser;
    assert_eq!(
        strict
            .get_owned(&strict_id)?
            .check(&browser, 1, &public())
            .denial,
        Some(EgressDenial::Transport)
    );
    let mut policy = open_policy();
    policy.preflight_transports = vec![EgressTransport::Browser];
    let (registry, id) = registry(policy)?;
    let scope = registry.get_owned(&id)?;
    let mut browser = request(id.clone(), "https://example.org/");
    browser.transport = EgressTransport::Browser;
    assert_eq!(scope.check(&browser, 1, &public()).denial, None);
    // Proxy was not opted in, and Unsupported can never be.
    for transport in [EgressTransport::Proxy, EgressTransport::Unsupported] {
        let mut other = request(id.clone(), "https://example.org/");
        other.transport = transport;
        assert_eq!(
            scope.check(&other, 1, &public()).denial,
            Some(EgressDenial::Transport)
        );
    }
    // The floor binds the browser preflight too.
    let mut metadata = request(id.clone(), "http://169.254.169.254/");
    metadata.transport = EgressTransport::Browser;
    assert_eq!(
        scope.check(&metadata, 1, &public()).denial,
        Some(EgressDenial::Address)
    );
    Ok(())
}
#[test]
fn local_capabilities_never_use_a_preflight_transport() -> R {
    let mut policy = open_policy();
    policy.open_public = false;
    policy.privacy = PrivacyMode::LocalOnly;
    policy.preflight_transports = vec![EgressTransport::Browser];
    policy.local_capabilities = vec![LocalEgressCapability {
        origin: "http://127.0.0.1:9000/".into(),
        path: "/health".into(),
        category: DataCategory::HostMetadata,
    }];
    let (registry, id) = registry(policy)?;
    let mut local = request(id.clone(), "http://127.0.0.1:9000/health");
    local.category = DataCategory::HostMetadata;
    local.local_capability = Some(0);
    let scope = registry.get_owned(&id)?;
    assert_eq!(scope.check(&local, 1, &public()).denial, None);
    local.transport = EgressTransport::Browser;
    assert_eq!(
        scope.check(&local, 1, &public()).denial,
        Some(EgressDenial::Transport)
    );
    Ok(())
}
#[test]
fn registration_rejects_ambiguous_or_unsound_open_and_preflight_settings() {
    let mut cases = Vec::new();
    let mut with_rules = open_policy();
    with_rules.destinations = vec![DestinationRule {
        scheme: "https".into(),
        hostname: "example.com".into(),
        port: 443,
        include_subdomains: false,
    }];
    cases.push(with_rules);
    let mut local_only = open_policy();
    local_only.privacy = PrivacyMode::LocalOnly;
    cases.push(local_only);
    let mut with_local = open_policy();
    with_local.local_capabilities = vec![LocalEgressCapability {
        origin: "http://127.0.0.1:9000/".into(),
        path: "/health".into(),
        category: DataCategory::HostMetadata,
    }];
    cases.push(with_local);
    for bad in [
        vec![EgressTransport::PinnedDirect],
        vec![EgressTransport::Unsupported],
        vec![EgressTransport::Browser, EgressTransport::Browser],
        vec![
            EgressTransport::Browser,
            EgressTransport::Proxy,
            EgressTransport::Browser,
        ],
    ] {
        let mut policy = open_policy();
        policy.preflight_transports = bad;
        cases.push(policy);
    }
    for policy in cases {
        let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
        assert!(registry.register(policy).is_err());
    }
    let mut both = open_policy();
    both.preflight_transports = vec![EgressTransport::Browser, EgressTransport::Proxy];
    let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
    assert!(registry.register(both).is_ok());
}
#[test]
fn sensitive_privacy_still_inspects_open_public_requests() -> R {
    let mut policy = open_policy();
    policy.privacy = PrivacyMode::Sensitive;
    let (registry, id) = registry(policy)?;
    let scope = registry.get_owned(&id)?;
    let mut leaking = request(id.clone(), "https://example.org/");
    leaking.method = "POST".into();
    leaking.payload = "mail alice@example.com".into();
    assert_eq!(
        scope.check(&leaking, 1, &public()).denial,
        Some(EgressDenial::Privacy)
    );
    assert_eq!(
        scope
            .check(&request(id.clone(), "https://example.org/"), 1, &public())
            .denial,
        None
    );
    Ok(())
}
#[test]
fn legacy_policy_json_without_the_new_fields_deserializes_closed() -> R {
    let json = serde_json::json!({
        "owner": {"user": "u", "workspace": "w", "agent": "a"},
        "ceiling": "full",
        "privacy": "standard",
        "destinations": [],
        "data_categories": ["user_content"],
        "local_capabilities": [],
        "validity_ms": 1000
    });
    let policy: EgressPolicy = serde_json::from_value(json)?;
    assert!(!policy.open_public);
    assert_eq!(policy.preflight_transports.len(), 0);
    Ok(())
}
