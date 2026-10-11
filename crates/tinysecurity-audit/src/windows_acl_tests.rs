use super::*;

#[test]
fn windows_protected_auto_inherited_dacl_retains_required_protection() {
    for flags in ["P", "PAI", "PAR", "PARAI", "PAIAR"] {
        assert!(protected(flags), "known protected control flags: {flags}");
    }
}

#[test]
fn windows_unprotected_unknown_or_duplicate_dacl_control_tokens_are_denied() {
    for flags in [
        "", "AI", "AR", "AIAR", "unknown", "Punknown", "PP", "PAIAI", "PARAR", "P AI", "P:A", "p",
    ] {
        assert!(!protected(flags), "unacceptable control flags: {flags}");
    }
}

#[test]
fn windows_null_absent_and_empty_dacls_are_rejected_before_native_acl_access() {
    for sddl in [
        "O:SY",
        "O:SYD:",
        "O:SYD:P",
        "O:SYD:NO_ACCESS_CONTROL",
        "O:SYD:PNO_ACCESS_CONTROL",
        "O:SYS:(AU;SA;FA;;;WD)",
        "O:SYD:PS:(AU;SA;FA;;;WD)",
    ] {
        assert!(!has_dacl_entries(sddl));
    }
    for sddl in [
        "O:SYD:P(A;OICI;FA;;;SY)",
        "O:SYD:(A;;FR;;;WD)S:(AU;SA;FA;;;WD)",
    ] {
        assert!(has_dacl_entries(sddl));
    }
}
