//! Content-free parsing of the DACL control section, independent of native handles.
pub(crate) fn protected(mut flags: &str) -> bool {
    // AI records completed automatic inheritance; AR requests that processing.
    // Neither clears P (inheritance protection) nor grants any ACE permission.
    // Actual owner/ACE checks remain separate and mandatory at the open handle.
    let mut seen = 0_u8;
    while !flags.is_empty() {
        let (bit, rest) = if let Some(rest) = flags.strip_prefix('P') {
            (1, rest)
        } else if let Some(rest) = flags.strip_prefix("AI") {
            (2, rest)
        } else if let Some(rest) = flags.strip_prefix("AR") {
            (4, rest)
        } else {
            return false;
        };
        if seen & bit != 0 {
            return false;
        }
        seen |= bit;
        flags = rest;
    }
    seen & 1 != 0
}
// A present NULL DACL permits everyone, but the safe dependency's native
// dacl() accessor panics for it. Check the canonical native SDDL first. This
// does not validate ACE rights: the existing handle checks still do that.
pub(crate) fn has_dacl_entries(sddl: &str) -> bool {
    sddl.split("D:")
        .nth(1)
        .and_then(|dacl| dacl.split("S:").next())
        .is_some_and(|dacl| dacl.contains('('))
}
#[cfg(test)]
#[path = "windows_acl_tests.rs"]
mod tests;
