//! Canonical authority and unconditional address floor.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tinysecurity_bus::{DestinationRule, EgressDenial};
use url::{Host, Url};
#[derive(Debug)]
pub(crate) struct Endpoint {
    pub(crate) url: Url,
    pub(crate) hostname: String,
    pub(crate) port: u16,
    pub(crate) ip: Option<IpAddr>,
}
pub(crate) fn parse(input: &str) -> Result<Endpoint, EgressDenial> {
    if input.len() > 8192
        || input.chars().any(|c| c.is_control() || c.is_whitespace())
        || input.contains('\\')
    {
        return Err(EgressDenial::Url);
    }
    let (_, remainder) = input.split_once("://").ok_or(EgressDenial::Url)?;
    let authority = remainder
        .split(['/', '?', '#'])
        .next()
        .ok_or(EgressDenial::Url)?;
    if authority.is_empty() || authority.contains(['@', '%']) {
        return Err(EgressDenial::Url);
    }
    // Reject empty and ambiguous ports before WHATWG normalization.
    let raw_host = if let Some(tail) = authority.strip_prefix('[') {
        let (host, port) = tail.split_once(']').ok_or(EgressDenial::Url)?;
        if !port.is_empty() {
            validate_port(port.strip_prefix(':').ok_or(EgressDenial::Url)?)?;
        }
        host
    } else {
        let (host, port) = authority
            .split_once(':')
            .map_or((authority, None), |(h, p)| (h, Some(p)));
        if let Some(port) = port {
            validate_port(port)?;
        }
        host
    };
    let mut url = Url::parse(input).map_err(|_| EgressDenial::Url)?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(EgressDenial::Url);
    }
    let (hostname, ip) = match url.host().ok_or(EgressDenial::Url)? {
        Host::Ipv4(ip) => {
            if raw_host != ip.to_string() {
                return Err(EgressDenial::Url);
            }
            (ip.to_string(), Some(IpAddr::V4(ip)))
        }
        Host::Ipv6(ip) => (ip.to_string(), Some(IpAddr::V6(ip))),
        Host::Domain(host) => {
            let host = host.trim_end_matches('.');
            if host.is_empty()
                || host.len() > 253
                || host.split('.').any(|part| {
                    part.is_empty()
                        || part.len() > 63
                        || part.starts_with('-')
                        || part.ends_with('-')
                        || !part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                })
            {
                return Err(EgressDenial::Url);
            }
            (host.to_owned(), None)
        }
    };
    if ip.is_none() {
        url.set_host(Some(&hostname))
            .map_err(|_| EgressDenial::Url)?;
    }
    let port = url.port_or_known_default().ok_or(EgressDenial::Url)?;
    Ok(Endpoint {
        url,
        hostname,
        port,
        ip,
    })
}
fn validate_port(port: &str) -> Result<(), EgressDenial> {
    if port.is_empty()
        || !port.bytes().all(|b| b.is_ascii_digit())
        || port.parse::<u16>().ok().is_none_or(|value| value == 0)
    {
        return Err(EgressDenial::Url);
    }
    Ok(())
}
pub(crate) fn normalize_rule(rule: &DestinationRule) -> Result<DestinationRule, EgressDenial> {
    if rule.port == 0
        || rule
            .hostname
            .contains(['/', '?', '#', '@', '%', '*', ':', '[', ']'])
            && rule.hostname.parse::<Ipv6Addr>().is_err()
    {
        return Err(EgressDenial::Url);
    }
    let hostname = if rule.hostname.parse::<Ipv6Addr>().is_ok() {
        format!("[{}]", rule.hostname)
    } else {
        rule.hostname.clone()
    };
    let endpoint = parse(&format!("{}://{}:{}/", rule.scheme, hostname, rule.port))?;
    if endpoint.ip.is_some_and(forbidden) || endpoint.ip.is_some() && rule.include_subdomains {
        return Err(EgressDenial::Address);
    }
    Ok(DestinationRule {
        scheme: endpoint.url.scheme().into(),
        hostname: endpoint.hostname,
        port: endpoint.port,
        include_subdomains: rule.include_subdomains,
    })
}
pub(crate) fn matches(rule: &DestinationRule, endpoint: &Endpoint) -> bool {
    rule.scheme == endpoint.url.scheme()
        && rule.port == endpoint.port
        && (rule.hostname == endpoint.hostname
            || rule.include_subdomains
                && endpoint
                    .hostname
                    .strip_suffix(&rule.hostname)
                    .is_some_and(|prefix| prefix.ends_with('.')))
}
pub(crate) fn forbidden(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => non_global_v4(ip),
        IpAddr::V6(ip) => non_global_v6(ip),
    }
}
fn non_global_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || a == 0
        || a >= 240
        || a == 100 && (64..=127).contains(&b)
        || a == 192 && (b == 0 && (c == 0 || c == 2) || b == 88 && c == 99)
        || a == 198 && (b == 51 && c == 100 || (18..=19).contains(&b))
        || a == 203 && b == 0 && c == 113
}
fn non_global_v6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    let embedded = |hi: u16, lo: u16| {
        let [first, second] = hi.to_be_bytes();
        let [third, fourth] = lo.to_be_bytes();
        non_global_v4(Ipv4Addr::new(first, second, third, fourth))
    };
    ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() || segments[0]&0xfe00==0xfc00 || segments[0]&0xffc0==0xfe80
    || segments[0]==0x2001 && (segments[1]==0xdb8 || segments[1]==2 && segments[2]==0) || segments[0]==0x100 && segments[1..3]==[0;2] && segments[3]<=1
    || segments[0]==0x64 && segments[1]==0xff9b && (segments[2]==1 || segments[2..6]==[0;4] && embedded(segments[6],segments[7]))
    || segments[0]==0x2002 && embedded(segments[1],segments[2]) || segments[..2]==[0x2001,0] && (embedded(!segments[6],!segments[7]) || embedded(segments[2],segments[3]))
    || segments[0]&0xfff0==0x3ff0 || segments[0]==0x5f00 || ip.to_ipv4().is_some_and(non_global_v4)
    // Only assigned global-unicast 2000::/3 and public IPv4 transition ranges above.
    || !(segments[0]&0xe000==0x2000 || segments[0]==0x64 && segments[1]==0xff9b && segments[2..6]==[0;4] || ip.to_ipv4().is_some())
}
#[cfg(test)]
#[path = "url_guard_tests.rs"]
mod tests;
