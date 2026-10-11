//! Reply parsing produces intent only, never human or execution authority.
use crate::{Error, Result, binding};
use tinysecurity_bus::{ParseReplyRequest, ParseReplyResponse, ReplyVerdict};
/// Parse bounded legacy vocabulary without persisting text or deciding any row.
/// # Errors
/// Rejects malformed request identities and oversized untrusted reply text.
pub fn parse_reply(request: &ParseReplyRequest) -> Result<ParseReplyResponse> {
    if !binding::hex(&request.request_id, 32) || request.reply.len() > 4096 {
        return Err(Error::Invalid);
    }
    let verdict = match request.reply.trim().to_ascii_lowercase().as_str() {
        "yes" | "y" | "ok" | "okay" | "approve" | "approved" | "allow" => ReplyVerdict::AllowOnce,
        "no" | "n" | "deny" | "denied" => ReplyVerdict::Deny,
        _ => ReplyVerdict::Unrecognized,
    };
    Ok(ParseReplyResponse { verdict })
}
#[cfg(test)]
#[path = "reply_tests.rs"]
mod tests;
