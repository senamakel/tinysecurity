use super::*;

#[test]
fn installer_diagnostics_accept_only_bounded_numeric_records() {
    let trace = b"audit-native-installer stage=1\r\naudit-native-installer stage=2\r\naudit-native-installer stage=3 error=5 hresult=-2146233087 native=0 command=0 wrapper=5 category=0\r\n";
    assert!(installer_diagnostics(trace).is_ok());
    assert!(installer_diagnostics(b"audit-native-installer stage=13 error=17 hresult=-2146233038 native=0 command=2 wrapper=11 category=18\n").is_ok());
    for invalid in [
        &b"private path or SID\n"[..],
        &b"audit-native-installer stage=15\n"[..],
        &b"audit-native-installer stage=3 error=99 hresult=0 native=0 command=0 wrapper=5 category=0\n"[..],
        &b"audit-native-installer stage=3 error=1 hresult=0 native=0 command=2\n"[..],
        &b"audit-native-installer stage=3 error=1 hresult=0 native=0 command=0 wrapper=5 category=0 secret\n"[..],
        &b"audit-native-installer stage=3 error=1 hresult=2147483648 native=0 command=0 wrapper=5 category=0\n"[..],
        &b"audit-native-installer stage=13 error=1 hresult=0 native=0 command=0 wrapper=32 category=0\n"[..],
        &b"audit-native-installer stage=13 error=1 hresult=0 native=0 command=0 wrapper=1 category=32\n"[..],
        &b"\xff\n"[..],
    ] {
        assert!(installer_diagnostics(invalid).is_err());
    }
}

#[test]
fn installer_diagnostics_reject_empty_oversized_and_legacy_streams() {
    assert!(installer_diagnostics(b"").is_err());
    assert!(installer_diagnostics(&vec![b'0'; 4097]).is_err());
    let line = "audit-native-installer stage=1\n";
    assert!(installer_diagnostics(line.repeat(15).as_bytes()).is_ok());
    assert!(installer_diagnostics(line.repeat(16).as_bytes()).is_err());
    assert!(
        installer_diagnostics(
            b"audit-native-installer stage=13 error=5 hresult=0 native=0 command=0\n"
        )
        .is_err()
    );
}

#[cfg(windows)]
#[test]
fn namespace_installer_succeeds_when_set_acl_cmdlet_is_unavailable() {
    let root = std::env::var_os("TINYSECURITY_AUDIT_TEST_ROOT")
        .expect("Windows CI must provision its protected audit root");
    let directory = tempfile::tempdir_in(root).unwrap();
    // Model the proven command-resolution failure without depending on the
    // runner's installed PowerShell modules. Any Set-Acl invocation must fail.
    let script = format!(
        "function Set-Acl {{ throw [System.Management.Automation.CommandNotFoundException]::new('fixture command unavailable') }}\n{NAMESPACE_INSTALL_SCRIPT}"
    );
    provision_with_script(directory.path(), &script).unwrap();
}
