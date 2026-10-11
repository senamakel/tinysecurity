use super::*;
#[test]
fn scoped_debug_is_content_free_even_when_nested() {
    let subject = SubjectScope {
        user: "private-user-needle".into(),
        workspace: "private-workspace-needle".into(),
        agent: "private-agent-needle".into(),
    };
    let header = EgressHeader {
        name: "private-header-name".into(),
        value: "private-header-value".into(),
    };
    let request = ScopedEgressRequest {
        policy_id: EgressPolicyId("private-policy-id".into()),
        subject: subject.clone(),
        tier: crate::AccessTier::Full,
        url: "https://private-url-needle.example/private-query".into(),
        method: "POST".into(),
        category: DataCategory::UserContent,
        payload: "private-body-needle".into(),
        headers: vec![header.clone()],
        transport: EgressTransport::PinnedDirect,
        local_capability: None,
        transformation: Some("private-transform-needle".into()),
    };
    let auth = TransportAuthorization {
        fingerprint: "private-fingerprint".into(),
        authorization_id: "private-auth-id".into(),
        url: request.url.clone(),
        hostname: "private-hostname".into(),
        port: 443,
        addresses: vec![],
        subject: subject.clone(),
        policy_id: request.policy_id.clone(),
        generation: 1,
        expires_at_ms: 42,
    };
    assert_eq!(format!("{header:?}"), "EgressHeader([REDACTED])");
    assert_eq!(format!("{request:?}"), "ScopedEgressRequest([REDACTED])");
    assert_eq!(format!("{auth:?}"), "TransportAuthorization([REDACTED])");
    let response = ScopedEgressResponse {
        generation: 1,
        denial: None,
        authorization: Some(auth.clone()),
        cacheable: false,
    };
    let consume = ConsumeEgressAuthorizationRequest {
        request,
        subject,
        authorization: auth,
    };
    for output in [
        format!("{response:?}"),
        format!("{consume:?}"),
        format!("{consume:#?}"),
    ] {
        assert!(!output.contains("private-"), "{output}");
    }
}
