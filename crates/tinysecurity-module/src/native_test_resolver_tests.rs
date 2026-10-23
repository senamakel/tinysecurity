use super::*;
use std::{net::IpAddr, time::Duration};
use tinysecurity::{ResolveFailure, Resolver};

#[test]
fn configured_answers_advance_once_per_resolution() -> Result<(), std::io::Error> {
    let resolver = FixtureResolver::parse(r#"{"rebind.test":["8.8.8.8","127.0.0.1"]}"#)
        .map_err(|_| std::io::Error::other("fixture should parse"))?;

    assert_eq!(
        resolver.resolve("rebind.test", Duration::from_secs(1), 8),
        Ok(vec![IpAddr::from([8, 8, 8, 8])])
    );
    assert_eq!(
        resolver.resolve("rebind.test", Duration::from_secs(1), 8),
        Ok(vec![IpAddr::from([127, 0, 0, 1])])
    );
    assert_eq!(
        resolver.resolve("rebind.test", Duration::from_secs(1), 8),
        Err(ResolveFailure)
    );
    Ok(())
}

#[test]
fn mixed_case_host_keys_match_canonical_queries() -> Result<(), std::io::Error> {
    let resolver = FixtureResolver::parse(r#"{"Rebind.Test":["8.8.8.8"]}"#)
        .map_err(|_| std::io::Error::other("valid mixed-case hostname should parse"))?;

    assert_eq!(
        resolver.resolve("rebind.test", Duration::from_secs(1), 8),
        Ok(vec![IpAddr::from([8, 8, 8, 8])])
    );
    Ok(())
}

#[test]
fn invalid_fixture_inputs_fail_closed() {
    for input in [
        "",
        "{}",
        r#"{"rebind.test":[]}"#,
        r#"{"bad host":["8.8.8.8"]}"#,
        r#"{"Rebind.Test":["8.8.8.8"],"rebind.test":["127.0.0.1"]}"#,
        r#"{"rebind.test":["8.8.8.8"],"rebind.test":["127.0.0.1"]}"#,
        r#"{"rebind.test":["not-an-ip"]}"#,
        &format!("{{\"{}\":[\"8.8.8.8\"]}}", "a".repeat(254)),
        &format!("{{\"rebind.test\":[{}]}}", ["\"8.8.8.8\""; 9].join(",")),
        &" ".repeat(MAX_FIXTURE_BYTES + 1),
    ] {
        assert!(FixtureResolver::parse(input).is_err());
    }
}
