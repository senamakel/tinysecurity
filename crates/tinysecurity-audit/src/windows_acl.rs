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
#[cfg(test)]
#[path = "windows_acl_tests.rs"]
mod tests;
