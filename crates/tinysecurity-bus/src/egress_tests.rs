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

#[test]
/// Browser authorization payloads expose no page identity or fabricated HTTP data.
fn browser_dial_contract_redacts_identity_and_serializes_no_http_payload()
-> Result<(), serde_json::Error> {
    let subject = SubjectScope {
        user: "private-user".into(),
        workspace: "private-workspace".into(),
        agent: "private-agent".into(),
    };
    let request = BrowserDialRequest {
        policy_id: EgressPolicyId("private-policy".into()),
        expected_generation: 9,
        session_id: "browser-session-private".into(),
        scheme: "https".into(),
        hostname: "private-destination.example".into(),
        port: 443,
    };
    let json = serde_json::to_value(&request)?;
    assert!(json.get("method").is_none());
    assert!(json.get("headers").is_none());
    assert!(json.get("payload").is_none());
    assert_eq!(format!("{request:?}"), "BrowserDialRequest([REDACTED])");
    let authorization = BrowserDialAuthorization {
        authorization_id: "private-nonce".into(),
        session_id: request.session_id.clone(),
        scheme: "https".into(),
        hostname: "private-destination.example".into(),
        port: 443,
        addresses: vec![std::net::SocketAddr::from(([8, 8, 8, 8], 443))],
        subject: subject.clone(),
        policy_id: request.policy_id.clone(),
        generation: 7,
        expires_at_ms: 10_000,
    };
    assert!(!format!("{authorization:?}").contains("private-"));
    let validate = ValidateBrowserDialRequest {
        authorization: authorization.clone(),
    };
    assert_eq!(
        format!("{validate:?}"),
        "ValidateBrowserDialRequest([REDACTED])"
    );
    let consume = ConsumeBrowserDialRequest {
        request,
        address: authorization.addresses[0],
        authorization,
    };
    assert!(!format!("{consume:#?}").contains("private-"));
    Ok(())
}

#[test]
fn browser_dial_wire_shapes_are_exact_and_round_trip() -> Result<(), serde_json::Error> {
    let subject = SubjectScope {
        user: "user".into(),
        workspace: "workspace".into(),
        agent: "agent".into(),
    };
    let policy_id = EgressPolicyId("policy-1".into());
    let request = BrowserDialRequest {
        policy_id: policy_id.clone(),
        expected_generation: 7,
        session_id: "session-1".into(),
        scheme: "https".into(),
        hostname: "example.com".into(),
        port: 443,
    };
    let request_wire = serde_json::json!({
        "policy_id": "policy-1",
        "expected_generation": 7,
        "session_id": "session-1",
        "scheme": "https",
        "hostname": "example.com",
        "port": 443
    });
    assert_eq!(serde_json::to_value(&request)?, request_wire);
    assert_eq!(
        serde_json::from_value::<BrowserDialRequest>(request_wire)?,
        request
    );

    let authorization = BrowserDialAuthorization {
        authorization_id: "nonce-1".into(),
        session_id: "session-1".into(),
        scheme: "https".into(),
        hostname: "example.com".into(),
        port: 443,
        addresses: vec![std::net::SocketAddr::from(([8, 8, 8, 8], 443))],
        subject: subject.clone(),
        policy_id: policy_id.clone(),
        generation: 7,
        expires_at_ms: 30_042,
    };
    let authorization_wire = serde_json::json!({
        "authorization_id": "nonce-1",
        "session_id": "session-1",
        "scheme": "https",
        "hostname": "example.com",
        "port": 443,
        "addresses": ["8.8.8.8:443"],
        "subject": {"user": "user", "workspace": "workspace", "agent": "agent"},
        "policy_id": "policy-1",
        "generation": 7,
        "expires_at_ms": 30042
    });
    assert_eq!(serde_json::to_value(&authorization)?, authorization_wire);
    assert_eq!(
        serde_json::from_value::<BrowserDialAuthorization>(authorization_wire.clone())?,
        authorization
    );

    let response = BrowserDialResponse {
        generation: 7,
        denial: None,
        authorization: Some(authorization.clone()),
    };
    let response_wire = serde_json::json!({
        "generation": 7,
        "denial": null,
        "authorization": authorization_wire
    });
    assert_eq!(serde_json::to_value(&response)?, response_wire);
    assert_eq!(
        serde_json::from_value::<BrowserDialResponse>(response_wire)?,
        response
    );

    let consume = ConsumeBrowserDialRequest {
        request: request.clone(),
        address: authorization.addresses[0],
        authorization: authorization.clone(),
    };
    let consume_wire = serde_json::json!({
        "request": request,
        "address": "8.8.8.8:443",
        "authorization": authorization
    });
    assert_eq!(serde_json::to_value(&consume)?, consume_wire);
    assert_eq!(
        serde_json::from_value::<ConsumeBrowserDialRequest>(consume_wire)?,
        consume
    );

    let validate = ValidateBrowserDialRequest { authorization };
    let validate_wire = serde_json::json!({
        "authorization": serde_json::to_value(&validate.authorization)?
    });
    assert_eq!(serde_json::to_value(&validate)?, validate_wire);
    assert_eq!(
        serde_json::from_value::<ValidateBrowserDialRequest>(validate_wire)?,
        validate
    );
    assert_eq!(
        serde_json::to_value(DataCategory::OpaqueBrowserTraffic)?,
        "opaque_browser_traffic"
    );
    assert_eq!(serde_json::to_value(EgressDenial::Stale)?, "stale");
    Ok(())
}
