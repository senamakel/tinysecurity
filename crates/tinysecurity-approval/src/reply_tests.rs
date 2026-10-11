use super::*;
#[test]
fn parses_bounded_intent_without_authority() -> Result<()> {
    for (text, expected) in [
        (" YES ", ReplyVerdict::AllowOnce),
        ("okay", ReplyVerdict::AllowOnce),
        ("N", ReplyVerdict::Deny),
        ("later", ReplyVerdict::Unrecognized),
    ] {
        assert_eq!(
            parse_reply(&ParseReplyRequest {
                request_id: "a".repeat(32),
                reply: text.into()
            })?
            .verdict,
            expected
        );
    }
    assert!(
        parse_reply(&ParseReplyRequest {
            request_id: "g".repeat(32),
            reply: "yes".into()
        })
        .is_err()
    );
    assert!(
        parse_reply(&ParseReplyRequest {
            request_id: "a".repeat(32),
            reply: "x".repeat(4097)
        })
        .is_err()
    );
    Ok(())
}
