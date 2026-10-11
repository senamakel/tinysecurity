//! Immutable shared redactor boundary before persistence or host callbacks.
use crate::{Error, Result};
use std::fmt::Write as _;
use tinysecurity_bus::{AuditSinkRequest2, RedactMode, RedactRequest};
use tinysecurity_redact::Redactor;
/// Allocate an opaque random event or stream identity once, before first delivery.
///
/// # Errors
/// Returns a content-free failure if operating-system entropy is unavailable.
pub fn opaque_id() -> Result<String> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| Error::Storage)?;
    let mut id = String::with_capacity(32);
    for byte in bytes {
        write!(&mut id, "{byte:02x}").map_err(|_| Error::Sanitation)?;
    }
    Ok(id)
}
/// Sanitize a complete batch using the active immutable registry.
///
/// Identities are pseudonymized; the trusted host maps durable scope handles.
/// Failed sanitation suppresses the complete original batch.
///
/// # Errors
/// Rejects malformed/oversized structured input, sequencing or unsafe rule identifiers.
pub fn sanitize(batch: &AuditSinkRequest2, redactor: &Redactor) -> Result<AuditSinkRequest2> {
    batch.validate().map_err(|_| Error::Sanitation)?;
    let redact = |text: &str, mode| {
        redactor
            .redact(&RedactRequest {
                text: text.into(),
                mode,
            })
            .map(|result| result.text)
            .map_err(|_| Error::Sanitation)
    };
    let mut clean = batch.clone();
    clean.scope.user = redact(&batch.scope.user, RedactMode::IdentifierHash)?;
    clean.scope.workspace = redact(&batch.scope.workspace, RedactMode::IdentifierHash)?;
    clean.scope.agent = redact(&batch.scope.agent, RedactMode::IdentifierHash)?;
    for event in &mut clean.events {
        event.attribution = redact(&event.attribution, RedactMode::Text)?;
        event.arguments_json = redact(&event.arguments_json, RedactMode::StructuredArguments)?;
        // Caller strings are not registry identities, even when identifier-shaped.
        if event.rule_ids.len() > 64
            || event.rule_ids.iter().any(|rule| {
                !matches!(
                    rule.as_str(),
                    "floor"
                        | "override.instructions"
                        | "override.role"
                        | "override.obfuscated_instructions"
                        | "exfiltrate.hidden_prompt"
                        | "exfiltrate.credentials"
                        | "tool.approval_bypass"
                        | "content.invisible_control"
                )
            })
        {
            return Err(Error::Sanitation);
        }
    }
    Ok(clean)
}
#[cfg(test)]
#[path = "event_tests.rs"]
mod tests;
