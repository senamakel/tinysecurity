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
