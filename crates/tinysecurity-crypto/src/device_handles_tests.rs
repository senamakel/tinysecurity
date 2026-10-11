use super::*;
use tinysecurity_bus::{AccessTier, DeviceScope2, SubjectScope};
type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
fn time(n: u64) -> Time {
    Time {
        wall: 1000 + n,
        monotonic: n,
    }
}
fn registration(id: &str) -> ApprovalScope2 {
    ApprovalScope2 {
        scope_id: id.into(),
        subject: SubjectScope {
            user: "user".into(),
            workspace: "workspace".into(),
            agent: format!("agent-{id}"),
        },
        policy_ref: "immutable".into(),
        generation: 1,
        ceiling: AccessTier::Full,
        require_approval: true,
        auto_approve_all: false,
    }
}
fn config() -> DeviceConfig2 {
    DeviceConfig2 {
        scopes: vec![
            DeviceScope2 {
                scope_id: "a".repeat(32),
                static_secret: Some([1; 32]),
            },
            DeviceScope2 {
                scope_id: "b".repeat(32),
                static_secret: Some([2; 32]),
            },
        ],
        max_handles: 16,
        max_in_flight: 2,
        operations_per_minute: 100,
        max_ttl_ms: 100,
        max_message_bytes: 1000,
        max_bootstrap_nonces: 2,
    }
}
fn registry() -> Result<Registry> {
    Registry::new(
        config(),
        &[registration(&"a".repeat(32)), registration(&"b".repeat(32))],
        ":1.1",
        1,
        time(0),
    )
}
fn request(scope: char, operation: DeviceOperation2) -> DeviceRequest2 {
    DeviceRequest2 {
        scope_id: scope.to_string().repeat(32),
        call_id: "call".into(),
        ttl_ms: 100,
        operation,
    }
}
fn run(reg: &Registry, scope: char, op: DeviceOperation2) -> Result<DeviceResponse2> {
    let request = request(scope, op);
    let work = reg.reserve(&request, 1, time(0))?;
    reg.execute(&work, &request.operation, 1, time(0))
}
fn key(reg: &Registry, scope: char, purpose: DeviceKeyPurpose2) -> Result<(String, String)> {
    let response = run(reg, scope, DeviceOperation2::Key { purpose })?;
    Ok((
        response.handle.ok_or(Error::DeviceDenied)?,
        response.public_key.ok_or(Error::DeviceDenied)?,
    ))
}
#[test]
fn authenticated_bootstrap_is_accepted_once_and_duplicate_is_denied() -> TestResult {
    let reg = registry()?;
    let (server, public) = key(&reg, 'a', DeviceKeyPurpose2::Static)?;
    let client = KeyPair::from_secret(Zeroizing::new([3; 32]))?;
    let frame = client.seal_handshake(PublicKey::decode(&public)?, b"fixture-private")?;
    let op = DeviceOperation2::OpenHandshake {
        handle: server,
        frame,
    };
    assert_eq!(run(&reg, 'a', op.clone())?.bytes, b"fixture-private");
    assert!(
        matches!(run(&reg, 'a', op), Err(Error::Replay)),
        "duplicate bootstrap must not grant authority twice"
    );
    Ok(())
}
