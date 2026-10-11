//! Owner shell scanning and classification, ported from the TinyBox/host characterization.
pub(crate) mod classify;
pub(crate) mod env_guard;
pub(crate) mod executor;
pub(crate) mod scan;

#[cfg(test)]
#[path = "command_shell_classify_tests.rs"]
mod classify_tests;
#[cfg(test)]
#[path = "command_shell_scan_tests.rs"]
mod scan_tests;
