//! `ScopedUrlGuard` acceptance: ambiguous authorities and forbidden literals are
//! refused before any DNS work, and the lease is bounded at registration.
use super::*;
use std::{net::IpAddr, sync::atomic::AtomicUsize};
use tinysecurity_bus::{AccessTier, DestinationRule, PrivacyMode};
type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
#[derive(Debug)]
struct Clock;
impl EgressClock for Clock {
    fn now_ms(&self) -> u64 {
        10
    }
}
#[derive(Debug, Default)]
struct CountingDns(AtomicUsize);
impl Resolver for CountingDns {
    fn resolve(
        &self,
        _: &str,
        _: Duration,
        _: usize,
    ) -> std::result::Result<Vec<IpAddr>, crate::ResolveFailure> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(vec![IpAddr::from([8, 8, 8, 8])])
    }
}
fn subject() -> SubjectScope {
    SubjectScope {
        user: "u".into(),
        workspace: "w".into(),
        agent: "a".into(),
    }
}
fn policy(validity_ms: u32) -> EgressPolicy {
    EgressPolicy {
        owner: subject(),
        ceiling: AccessTier::Full,
        privacy: PrivacyMode::Standard,
        destinations: vec![DestinationRule {
            scheme: "http".into(),
            hostname: "example.com".into(),
            port: 80,
            include_subdomains: true,
        }],
        data_categories: vec![DataCategory::UserContent],
        local_capabilities: vec![],
        validity_ms,
        open_public: false,
        preflight_transports: vec![],
    }
}
fn request(id: &EgressPolicyId, url: &str) -> ScopedEgressRequest {
    ScopedEgressRequest {
        policy_id: id.clone(),
        subject: subject(),
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
#[test]
fn guard_refuses_ambiguous_and_forbidden_authorities_without_resolving() -> TestResult {
    let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
    let id = registry.register(policy(500))?;
    let scope = registry.get_owned(&id)?;
    let redactor = Redactor::new(&RedactorConfig::default())?;
    for url in [
        // Cloud metadata, link-local and loopback literals.
        "http://169.254.169.254/latest/meta-data",
        "http://127.0.0.1/",
        "http://[::1]/",
        // CGNAT and RFC 1918.
        "http://100.64.0.1/",
        "http://10.1.2.3/",
        // IPv4-mapped / translated IPv6 forms of forbidden addresses.
        "http://[::ffff:169.254.169.254]/",
        "http://[::ffff:a9fe:a9fe]/",
        "http://[64:ff9b::a9fe:a9fe]/",
        "http://[2002:a9fe:a9fe::1]/",
        // Numeric IPv4 spellings that a resolver would read as loopback/metadata.
        "http://2130706433/",
        "http://0x7f000001/",
        "http://0177.0.0.1/",
        "http://127.1/",
        "http://2852039166/",
        // Zone identifiers, userinfo and percent-encoded authority.
        "http://[fe80::1%25eth0]/",
        "http://[fe80::1%eth0]/",
        "http://user:pass@example.com/",
        "http://example.com@127.0.0.1/",
        "http://example.com%2f@127.0.0.1/",
        "http://%31%32%37.0.0.1/",
        // Allowed host with a suffix trick or a different port/scheme.
        "http://evilexample.com/",
        "http://example.com:8080/",
        "https://example.com/",
    ] {
        let dns = CountingDns::default();
        let result = scope.url_guard(&request(&id, url), 1, &dns, &redactor);
        assert!(
            result.denial.is_some() && result.authorization.is_none(),
            "{url} was authorized"
        );
        assert!(!result.cacheable, "{url}");
        assert_eq!(dns.0.load(Ordering::SeqCst), 0, "{url} reached DNS");
    }
    Ok(())
}
#[test]
fn guard_returns_hostname_and_only_the_exact_approved_addresses() -> TestResult {
    let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
    let id = registry.register(policy(500))?;
    let scope = registry.get_owned(&id)?;
    let redactor = Redactor::new(&RedactorConfig::default())?;
    let dns = CountingDns::default();
    let result = scope.url_guard(
        &request(&id, "http://Api.Example.COM./x"),
        3,
        &dns,
        &redactor,
    );
    let grant = result.authorization.ok_or("denied")?;
    assert_eq!(grant.hostname, "api.example.com");
    assert_eq!(grant.addresses, vec!["8.8.8.8:80".parse()?]);
    assert_eq!(grant.expires_at_ms, 510);
    assert_eq!(grant.generation, 3);
    assert_eq!(dns.0.load(Ordering::SeqCst), 1);
    Ok(())
}
#[test]
fn lease_validity_is_bounded_at_registration() {
    for ok in [1, 30_000] {
        let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
        assert!(registry.register(policy(ok)).is_ok(), "{ok}");
    }
    for bad in [0, 30_001, u32::MAX] {
        let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
        assert!(registry.register(policy(bad)).is_err(), "{bad}");
    }
}
#[test]
fn forbidden_addresses_cannot_be_registered_as_destinations() {
    for host in [
        "169.254.169.254",
        "100.64.0.1",
        "127.0.0.1",
        "::1",
        "::ffff:10.0.0.1",
    ] {
        let mut candidate = policy(500);
        candidate.destinations = vec![DestinationRule {
            scheme: "http".into(),
            hostname: host.into(),
            port: 80,
            include_subdomains: false,
        }];
        let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
        assert!(registry.register(candidate).is_err(), "{host}");
    }
}
#[test]
fn sensitive_mode_denies_credentials_in_any_original_part_and_allows_ordinary_data() -> TestResult {
    let mut sensitive = policy(500);
    sensitive.privacy = PrivacyMode::Sensitive;
    let mut registry = EgressPolicyRegistry::with_clock(Arc::new(Clock));
    let id = registry.register(sensitive)?;
    let scope = registry.get_owned(&id)?;
    let redactor = Redactor::new(&RedactorConfig::default())?;
    let dns = CountingDns::default();
    let send = |url: &str, payload: &str| {
        let mut req = request(&id, url);
        req.method = "POST".into();
        req.payload = payload.into();
        scope.url_guard(&req, 1, &dns, &redactor)
    };
    assert!(
        send("http://example.com/a", "meeting notes for tuesday")
            .authorization
            .is_some()
    );
    for (url, payload) in [
        (
            "http://example.com/a",
            "token xoxb-123456789012-Zq9XyWvUtSrQ",
        ),
        (
            "http://example.com/a",
            "Authorization: Bearer opaque-credential",
        ),
        ("http://example.com/a", "mail alice@example.org"),
        (
            "http://example.com/a?key=sk_live_Zq9XyWvUtSrQpOnMlKjIh",
            "x",
        ),
        ("http://example.com/alice%40example.org", "x"),
    ] {
        let result = send(url, payload);
        assert_eq!(
            result.denial,
            Some(EgressDenial::Privacy),
            "{url} {payload}"
        );
    }
    // Classification cannot be downgraded to reach credentials or identifiers.
    for category in [
        DataCategory::Credentials,
        DataCategory::Identifiers,
        DataCategory::Unknown,
    ] {
        let mut req = request(&id, "http://example.com/a");
        req.category = category;
        assert!(scope.url_guard(&req, 1, &dns, &redactor).denial.is_some());
    }
    Ok(())
}
