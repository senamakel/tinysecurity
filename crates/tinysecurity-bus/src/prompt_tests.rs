use super::*;
#[test]
fn exact_prompt_binding_does_not_convert_human_intent_into_permission() {
    let request = ApprovalPromptRequest2 {
        scope: SubjectScope {
            user: "user".into(),
            workspace: "workspace".into(),
            agent: "agent".into(),
        },
        prompt_id: "a".repeat(32),
        record: ApprovalRecord2 {
            record_id: "b".repeat(32),
            version: 1,
            policy_id: "policy".into(),
            generation: 1,
            fingerprint: "c".repeat(32),
            record_json: "{}".into(),
        },
        summary: "private-summary".into(),
        timeout_ms: 100,
    };
    let response = ApprovalPromptResponse2 {
        scope: request.scope.clone(),
        prompt_id: request.prompt_id.clone(),
        record_id: request.record.record_id.clone(),
        fingerprint: request.record.fingerprint.clone(),
        decision: None,
    };
    assert_eq!(request.verify_response(&response), Ok(()));
    for index in 0..5 {
        let mut unrelated = response.clone();
        match index {
            0 => unrelated.scope.user.push('x'),
            1 => unrelated.prompt_id.push('x'),
            2 => unrelated.record_id.push('x'),
            3 => unrelated.fingerprint.push('x'),
            _ => {
                unrelated.decision = Some(ApprovalPromptDecision2 {
                    actor_id: String::new(),
                    verdict: ReplyVerdict::AllowOnce,
                });
            }
        }
        assert_eq!(
            request.verify_response(&unrelated),
            Err(crate::Error::InvalidArguments)
        );
    }
    assert!(
        !format!(
            "{:?}{:?}{:?}",
            request,
            response,
            ApprovalPromptDecision2 {
                actor_id: "private-actor".into(),
                verdict: ReplyVerdict::Deny
            }
        )
        .contains("private-")
    );
}
