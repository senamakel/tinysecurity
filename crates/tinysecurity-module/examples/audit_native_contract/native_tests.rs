use super::*;

#[test]
fn installer_diagnostics_accept_only_bounded_numeric_records() {
    let trace = b"audit-native-installer stage=1\r\naudit-native-installer stage=2\r\naudit-native-installer stage=3 error=5 hresult=-2146233087 native=0 command=0\r\n";
    assert!(installer_diagnostics(trace).is_ok());
    for invalid in [
        &b"private path or SID\n"[..],
        &b"audit-native-installer stage=15\n"[..],
        &b"audit-native-installer stage=3 error=99 hresult=0 native=0 command=0\n"[..],
        &b"audit-native-installer stage=3 error=1 hresult=0 native=0 command=2\n"[..],
        &b"audit-native-installer stage=3 error=1 hresult=0 native=0 command=0 secret\n"[..],
        &b"audit-native-installer stage=3 error=1 hresult=2147483648 native=0 command=0\n"[..],
        &b"\xff\n"[..],
    ] {
        assert!(installer_diagnostics(invalid).is_err());
    }
}
