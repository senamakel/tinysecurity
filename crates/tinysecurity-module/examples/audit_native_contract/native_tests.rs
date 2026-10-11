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
