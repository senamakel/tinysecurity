use super::*;
#[test]
fn url_guard_rejects_forbidden_literals_before_dns() -> Result<(), Box<dyn std::error::Error>> {
    for ip in [
        "169.254.169.254",
        "100.64.0.1",
        "100.127.255.255",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.0.1",
        "127.99.1.1",
        "0.9.1.1",
        "224.0.0.1",
        "240.0.0.1",
        "192.0.2.1",
        "198.51.100.1",
        "203.0.113.1",
        "198.18.0.1",
        "::1",
        "::",
        "fe80::1",
        "fc00::1",
        "fd00::1",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "64:ff9b::a00:1",
        "64:ff9b:1::1",
        "2002:a00:1::1",
        "2001:0:808:808:0:0:f5ff:fffe",
        "2001:db8::1",
        "ff02::1",
        "fec0::1",
    ] {
        assert!(forbidden(ip.parse()?), "{ip}");
    }
    for ip in [
        "8.8.8.8",
        "1.1.1.1",
        "2606:4700:4700::1111",
        "2002:808:808::1",
        "64:ff9b::808:808",
    ] {
        assert!(!forbidden(ip.parse()?), "{ip}");
    }
    Ok(())
}
#[test]
fn url_guard_rejects_ambiguous_authority() {
    for url in [
        "http://2130706433",
        "http://0177.0.0.1",
        "http://0x7f000001",
        "http://127.1",
        "http://001.2.3.4",
        "http://[fe80::1%25eth0]",
        "https://user:pass@example.com",
        "https://127.0.0.1:80@example.com",
        "https://public.com\\@127.0.0.1",
        "https://%65xample.com",
        "https://example.com:",
        "https://example.com:0",
        "https://example.com:99999",
        "https://exa mple.com",
        "https://example.com\0",
        "file:///tmp/a",
        "ftp://example.com",
        "data:x",
        "javascript:x",
        "https:///example.com",
        "https://example..com",
        "https://-a.com",
    ] {
        assert!(parse(url).is_err(), "{url:?}");
    }
    for url in [
        "https://EXAMPLE.COM./a%20b?q=%ff",
        "https://bücher.example/",
        "https://[2606:4700:4700::1111]/",
    ] {
        assert!(parse(url).is_ok(), "{url}");
    }
}
#[test]
fn registered_rules_are_canonical_and_suffix_safe() -> Result<(), Box<dyn std::error::Error>> {
    let rule = normalize_rule(&DestinationRule {
        scheme: "https".into(),
        hostname: "BÜCHER.example.".into(),
        port: 443,
        include_subdomains: true,
    })
    .map_err(|_| "invalid rule")?;
    assert_eq!(rule.hostname, "xn--bcher-kva.example");
    assert!(matches(
        &rule,
        &parse("https://child.xn--bcher-kva.example/").map_err(|_| "invalid URL")?
    ));
    assert!(!matches(
        &rule,
        &parse("https://evilxn--bcher-kva.example/").map_err(|_| "invalid URL")?
    ));
    assert!(!matches(
        &rule,
        &parse("http://xn--bcher-kva.example/").map_err(|_| "invalid URL")?
    ));
    Ok(())
}
