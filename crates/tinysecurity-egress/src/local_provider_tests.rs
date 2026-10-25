use super::*;

use tinysecurity_bus::ProviderEndpointLocality2::{External, OnDevice};

#[test]
fn classifies_only_same_machine_reserved_provider_hosts_as_on_device() {
    for host in [
        "localhost",
        "worker.localhost",
        "127.0.0.1",
        "127.25.3.4",
        "0.0.0.0",
        "[::1]",
        "[::]",
        "[::ffff:127.0.0.1]",
    ] {
        assert_eq!(classify_provider_endpoint(host), OnDevice, "{host}");
    }
}

#[test]
fn treats_lan_and_non_loopback_reserved_addresses_as_external() {
    for host in [
        "192.168.1.5",
        "10.0.0.8",
        "172.16.0.2",
        "169.254.1.2",
        "[fe80::1]",
        "[fd00::1]",
        "example.local",
        "localhost.example",
        "not a host",
    ] {
        assert_eq!(classify_provider_endpoint(host), External, "{host}");
    }
}
