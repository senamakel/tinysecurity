use super::*;
use std::{
    net::IpAddr,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use tinysecurity_bus::{AccessTier, DestinationRule, LocalEgressCapability, PrivacyMode};
#[derive(Debug)]
struct Clock;
impl EgressClock for Clock {
    fn now_ms(&self) -> u64 {
        42
    }
}
#[derive(Debug)]
struct Dns {
    calls: AtomicUsize,
    answers: Vec<IpAddr>,
}
impl Resolver for Dns {
    fn resolve(
        &self,
        _: &str,
        _: Duration,
        _: usize,
    ) -> std::result::Result<Vec<IpAddr>, crate::ResolveFailure> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.answers.clone())
    }
}
fn owner() -> SubjectScope {
    SubjectScope {
        user: "user".into(),
        workspace: "workspace".into(),
        agent: "agent".into(),
    }
}
fn policy() -> EgressPolicy {
    EgressPolicy {
        owner: owner(),
        ceiling: AccessTier::Full,
        privacy: PrivacyMode::Standard,
        destinations: vec![DestinationRule {
            scheme: "https".into(),
            hostname: "example.com".into(),
            port: 8443,
            include_subdomains: true,
        }],
        data_categories: vec![DataCategory::UserContent, DataCategory::HostMetadata],
        local_capabilities: vec![],
        validity_ms: 1000,
    }
}
fn request(id: EgressPolicyId) -> ScopedEgressRequest {
    ScopedEgressRequest {
        policy_id: id,
        subject: owner(),
        tier: AccessTier::Full,
        url: "https://Example.COM:8443/a%20b?q=1".into(),
        method: "POST".into(),
        category: DataCategory::UserContent,
        payload: "ordinary content".into(),
        headers: vec![],
        transport: EgressTransport::PinnedDirect,
        local_capability: None,
        transformation: None,
    }
}
#[derive(Debug)]
struct Failed;
impl Resolver for Failed {
    fn resolve(
        &self,
        _: &str,
        timeout: Duration,
        limit: usize,
    ) -> std::result::Result<Vec<IpAddr>, crate::ResolveFailure> {
        assert_eq!(timeout, Duration::from_secs(2));
        assert_eq!(limit, 64);
        Err(crate::ResolveFailure)
    }
}
#[test]
fn url_guard_returns_scoped_exact_vetted_transport_authorization()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
    let id = registry.register(policy())?;
    let dns = Dns {
        calls: AtomicUsize::new(0),
        answers: vec!["8.8.8.8".parse()?, "2606:4700:4700::1111".parse()?],
    };
    let result = registry
        .get_owned(&id)?
        .check(&request(id.clone()), 7, &dns);
    assert_eq!(result.denial, None);
    assert!(!result.cacheable);
    let auth = result.authorization.ok_or("missing authorization")?;
    assert_eq!(auth.hostname, "example.com");
    assert_eq!(auth.port, 8443);
    assert_eq!(auth.addresses.len(), 2);
    assert_eq!(auth.subject, owner());
    assert_eq!(auth.policy_id, id);
    assert_eq!(auth.generation, 7);
    assert_eq!(auth.expires_at_ms, 1042);
    assert_eq!(dns.calls.load(Ordering::SeqCst), 1);
    Ok(())
}
#[test]
fn invalid_registration_is_atomic_and_scopes_are_isolated()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
    let id = registry.register(policy())?;
    let mut invalid = policy();
    invalid.destinations[0].hostname = "*.example.com".into();
    assert!(registry.register(invalid).is_err());
    let mut second = policy();
    second.owner.user = "other".into();
    let second_id = registry.register(second)?;
    assert_ne!(id, second_id);
    let dns = Dns {
        calls: AtomicUsize::new(0),
        answers: vec!["8.8.8.8".parse()?],
    };
    let mut req = request(id.clone());
    req.subject.user = "other".into();
    assert_eq!(
        registry.get_owned(&id)?.check(&req, 1, &dns).denial,
        Some(EgressDenial::Scope)
    );
    assert_eq!(dns.calls.load(Ordering::SeqCst), 0);
    assert!(
        registry
            .get_owned(&EgressPolicyId("unknown".into()))
            .is_err()
    );
    Ok(())
}
#[test]
fn url_guard_denies_any_forbidden_dns_candidate_and_bounded_failures()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
    let id = registry.register(policy())?;
    let scope = registry.get_owned(&id)?;
    for ips in [
        vec!["8.8.8.8", "10.0.0.1"],
        vec!["fd00::1", "8.8.8.8"],
        vec![],
        vec!["8.8.8.8"; 65],
    ] {
        let dns = Dns {
            calls: AtomicUsize::new(0),
            answers: ips
                .iter()
                .map(|ip| ip.parse())
                .collect::<std::result::Result<_, _>>()?,
        };
        assert!(scope.check(&request(id.clone()), 1, &dns).denial.is_some());
    }
    assert_eq!(
        scope.check(&request(id.clone()), 1, &Failed).denial,
        Some(EgressDenial::Resolver)
    );
    let dns = Dns {
        calls: AtomicUsize::new(0),
        answers: vec!["8.8.8.8".parse()?; 3],
    };
    assert_eq!(
        scope
            .check(&request(id), 1, &dns)
            .authorization
            .ok_or("missing")?
            .addresses
            .len(),
        1
    );
    Ok(())
}
#[test]
fn local_only_blocks_all_external_routes_before_dns_and_local_capability_is_narrow()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
    let mut config = policy();
    config.privacy = PrivacyMode::LocalOnly;
    config.local_capabilities.push(LocalEgressCapability {
        origin: "http://127.0.0.1:11434".into(),
        path: "/health".into(),
        category: DataCategory::HostMetadata,
    });
    let id = registry.register(config)?;
    let scope = registry.get_owned(&id)?;
    let dns = Dns {
        calls: AtomicUsize::new(0),
        answers: vec!["8.8.8.8".parse()?],
    };
    let mut req = request(id);
    assert_eq!(
        scope.check(&req, 1, &dns).denial,
        Some(EgressDenial::Privacy)
    );
    req.local_capability = Some(0);
    assert!(scope.check(&req, 1, &dns).denial.is_some());
    req.url = "http://127.0.0.1:11434/health".into();
    req.category = DataCategory::HostMetadata;
    assert_eq!(scope.check(&req, 1, &dns).denial, None);
    for url in [
        "http://127.0.0.1:11434/api/chat",
        "http://127.0.0.1:11434/health?q=x",
        "http://127.0.0.1:11434/health#x",
        "http://169.254.169.254:11434/health",
    ] {
        req.url = url.into();
        assert!(scope.check(&req, 1, &dns).denial.is_some());
    }
    req.url = "http://127.0.0.1:11434/health".into();
    req.local_capability = None;
    assert!(scope.check(&req, 1, &dns).denial.is_some());
    assert_eq!(dns.calls.load(Ordering::SeqCst), 0);
    Ok(())
}
#[test]
fn standard_and_sensitive_enforce_original_data_and_destination()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let dns = Dns {
        calls: AtomicUsize::new(0),
        answers: vec!["8.8.8.8".parse()?],
    };
    let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
    let mut config = policy();
    config.privacy = PrivacyMode::Sensitive;
    let id = registry.register(config)?;
    let scope = registry.get_owned(&id)?;
    let mut req = request(id);
    req.url = "https://example.com:8443/path".into();
    assert_eq!(scope.check(&req, 1, &dns).denial, None);
    for category in [
        DataCategory::Unknown,
        DataCategory::Credentials,
        DataCategory::Identifiers,
    ] {
        req.category = category;
        assert_eq!(
            scope.check(&req, 1, &dns).denial,
            Some(EgressDenial::Privacy)
        );
    }
    req.category = DataCategory::UserContent;
    for payload in [
        "bearer raw-private-token",
        "email me at person@example.com",
        "{\"password\":\"raw-secret\"}",
    ] {
        req.payload = payload.into();
        assert_eq!(
            scope.check(&req, 1, &dns).denial,
            Some(EgressDenial::Privacy)
        );
    }
    req.payload = "ordinary content".into();
    req.transformation = Some("fake-approved".into());
    assert_eq!(
        scope.check(&req, 1, &dns).denial,
        Some(EgressDenial::Privacy)
    );
    req.transformation = None;
    req.url = "https://evil-example.com:8443/".into();
    assert_eq!(
        scope.check(&req, 1, &dns).denial,
        Some(EgressDenial::Destination)
    );
    for transport in [
        EgressTransport::Browser,
        EgressTransport::Proxy,
        EgressTransport::Unsupported,
    ] {
        req.transport = transport;
        assert_eq!(
            scope.check(&req, 1, &dns).denial,
            Some(EgressDenial::Transport)
        );
    }
    Ok(())
}
#[derive(Debug)]
struct MutableClock(std::sync::atomic::AtomicU64);
impl EgressClock for MutableClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}
#[test]
fn lease_expires_and_clock_rollback_cannot_extend_permission()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let clock = Arc::new(MutableClock(std::sync::atomic::AtomicU64::new(1000)));
    let mut registry = EgressPolicyRegistry::with_clock(clock.clone());
    let id = registry.register(policy())?;
    let scope = registry.get_owned(&id)?;
    let dns = Dns {
        calls: AtomicUsize::new(0),
        answers: vec!["8.8.8.8".parse()?],
    };
    let req = request(id);
    let auth = scope.check(&req, 7, &dns).authorization.ok_or("missing")?;
    assert!(scope.valid(&auth, &owner(), 7));
    assert!(!scope.valid(&auth, &owner(), 8));
    clock.0.store(2000, Ordering::SeqCst);
    assert!(!scope.valid(&auth, &owner(), 7));
    clock.0.store(1000, Ordering::SeqCst);
    assert!(!scope.valid(&auth, &owner(), 7));
    assert_eq!(scope.check(&req, 7, &dns).denial, Some(EgressDenial::Stale));
    Ok(())
}
#[test]
fn lease_validation_rejects_tampered_addresses_or_destination()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
    let id = registry.register(policy())?;
    let scope = registry.get_owned(&id)?;
    let dns = Dns {
        calls: AtomicUsize::new(0),
        answers: vec!["8.8.8.8".parse()?],
    };
    let mut auth = scope
        .check(&request(id), 7, &dns)
        .authorization
        .ok_or("missing")?;
    auth.addresses = vec!["127.0.0.1:8443".parse()?];
    assert!(!scope.valid(&auth, &owner(), 7));
    Ok(())
}
#[test]
fn consume_is_exact_once_and_replayed_grants_deny()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
    let id = registry.register(policy())?;
    let scope = registry.get_owned(&id)?;
    let dns = Dns {
        calls: AtomicUsize::new(0),
        answers: vec!["8.8.8.8".parse()?],
    };
    let auth = scope
        .check(&request(id), 7, &dns)
        .authorization
        .ok_or("missing")?;
    let mut other = owner();
    other.agent = "other-agent".into();
    assert!(!scope.consume(&auth, &other, 7));
    assert!(!scope.consume(&auth, &owner(), 8));
    assert!(scope.consume(&auth, &owner(), 7));
    assert!(!scope.consume(&auth, &owner(), 7));
    assert!(!scope.valid(&auth, &owner(), 7));
    Ok(())
}
#[test]
fn privacy_and_address_floor_cannot_be_overridden_by_configured_destination()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
    for hostname in [
        "127.0.0.1",
        "169.254.169.254",
        "10.0.0.1",
        "*",
        "*.example.com",
        "[::1]",
    ] {
        let mut bad = policy();
        bad.destinations[0].hostname = hostname.into();
        assert!(registry.register(bad).is_err());
    }
    let mut config = policy();
    config.destinations.clear();
    let id = registry.register(config)?;
    let dns = Dns {
        calls: AtomicUsize::new(0),
        answers: vec!["8.8.8.8".parse()?],
    };
    let mut req = request(id.clone());
    assert_eq!(
        registry.get_owned(&id)?.check(&req, 1, &dns).denial,
        Some(EgressDenial::Destination)
    );
    req.url = "http://127.0.0.1/".into();
    assert_eq!(
        registry.get_owned(&id)?.check(&req, 1, &dns).denial,
        Some(EgressDenial::Address)
    );
    assert_eq!(dns.calls.load(Ordering::SeqCst), 0);
    Ok(())
}
#[test]
fn generic_url_guard_cannot_use_narrow_host_local_capability()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
    let mut config = policy();
    config.local_capabilities.push(LocalEgressCapability {
        origin: "http://127.0.0.1:11434".into(),
        path: "/health".into(),
        category: DataCategory::HostMetadata,
    });
    let id = registry.register(config)?;
    let scope = registry.get_owned(&id)?;
    let mut req = request(id);
    req.category = DataCategory::HostMetadata;
    req.local_capability = Some(0);
    req.url = "http://127.0.0.1:11434/health".into();
    let dns = Dns {
        calls: AtomicUsize::new(0),
        answers: vec![],
    };
    let redactor = Redactor::new(&RedactorConfig::default())?;
    assert_eq!(
        scope.url_guard(&req, 1, &dns, &redactor).denial,
        Some(EgressDenial::Address)
    );
    assert_eq!(dns.calls.load(Ordering::SeqCst), 0);
    Ok(())
}
#[test]
fn sensitive_inspects_original_url_headers_and_payload_before_dns()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
    let mut config = policy();
    config.privacy = PrivacyMode::Sensitive;
    let id = registry.register(config)?;
    let scope = registry.get_owned(&id)?;
    let dns = Dns {
        calls: AtomicUsize::new(0),
        answers: vec!["8.8.8.8".parse()?],
    };
    let mut req = request(id);
    req.url = "https://example.com:8443/path".into();
    for url in [
        "https://example.com:8443/path?api_key=raw-private-token",
        "https://example.com:8443/path#person@example.com",
        "https://example.com:8443/person%40example.com",
    ] {
        req.url = url.into();
        assert_eq!(
            scope.check(&req, 1, &dns).denial,
            Some(EgressDenial::Privacy)
        );
    }
    req.url = "https://example.com:8443/path".into();
    for (name, value) in [
        ("Authorization", "Bearer raw-token"),
        ("X-User-Id", "opaque-identifier"),
        ("X-Comment", "person@example.com"),
        ("Host", "127.0.0.1"),
        ("X-Test", "line\r\nHost: evil"),
    ] {
        req.headers = vec![tinysecurity_bus::EgressHeader {
            name: name.into(),
            value: value.into(),
        }];
        assert_eq!(
            scope.check(&req, 1, &dns).denial,
            Some(EgressDenial::Privacy)
        );
    }
    assert_eq!(dns.calls.load(Ordering::SeqCst), 0);
    req.headers = vec![tinysecurity_bus::EgressHeader {
        name: "User-Agent".into(),
        value: "fixture".into(),
    }];
    assert_eq!(scope.check(&req, 1, &dns).denial, None);
    Ok(())
}
#[test]
fn actual_outgoing_operation_changes_invalidate_the_grant()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
    let id = registry.register(policy())?;
    let scope = registry.get_owned(&id)?;
    let req = request(id);
    let dns = Dns {
        calls: AtomicUsize::new(0),
        answers: vec!["8.8.8.8".parse()?],
    };
    let auth = scope.check(&req, 7, &dns).authorization.ok_or("missing")?;
    let mut changed = req.clone();
    changed.payload = "different body".into();
    assert!(!scope.consume_request(&changed, &auth, &owner(), 7));
    changed = req.clone();
    changed.headers = vec![tinysecurity_bus::EgressHeader {
        name: "Authorization".into(),
        value: "Bearer private-token".into(),
    }];
    assert!(!scope.consume_request(&changed, &auth, &owner(), 7));
    assert!(scope.consume_request(&req, &auth, &owner(), 7));
    Ok(())
}
