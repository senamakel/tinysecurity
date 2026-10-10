use super::*;
#[test]
fn system_resolver_rejects_unbounded_requests_without_dns() {
    let resolver = SystemResolver;
    for (host, timeout, limit) in [
        ("example.invalid".to_owned(), Duration::ZERO, 64),
        ("x".repeat(254), Duration::from_secs(1), 64),
        ("example.invalid".to_owned(), Duration::from_secs(3), 64),
        ("example.invalid".to_owned(), Duration::from_secs(1), 0),
        ("example.invalid".to_owned(), Duration::from_secs(1), 65),
    ] {
        assert_eq!(resolver.resolve(&host, timeout, limit), Err(ResolveFailure));
    }
}
#[test]
fn system_resolver_accepts_literal_without_external_service()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        SystemResolver
            .resolve("8.8.8.8", Duration::from_secs(1), 64)
            .map_err(|_| "resolve failed")?,
        vec!["8.8.8.8".parse::<IpAddr>()?]
    );
    Ok(())
}
