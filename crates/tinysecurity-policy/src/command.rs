//! Conservative shell bootstrap: only argument-free read diagnostics.
//!
//! The host's rich shell grammar is not claimed migrated here. Substitution,
//! scripts, executable paths, redirection and compound commands fail closed.
use crate::{DenialReason, PolicyConfig, path};
pub(super) fn check(config: &PolicyConfig, command: &str) -> std::result::Result<(), DenialReason> {
    // Apply the same credential/system floor even when discretionary policy is off.
    // Unknown shell constructs cannot hide paths because they are never allowed.
    if command.split_whitespace().any(path::floor) {
        return Err(DenialReason::Floor);
    }
    let command = command.trim();
    if !matches!(command, "pwd" | "date" | "uname" | "whoami") {
        return Err(DenialReason::Command);
    }
    if config.enabled
        && !config
            .allowed_commands
            .iter()
            .any(|allowed| allowed == command)
    {
        return Err(DenialReason::Command);
    }
    Ok(())
}
