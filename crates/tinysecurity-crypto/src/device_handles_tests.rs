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

#[test]
fn static_key_aliases_cannot_bypass_bootstrap_replay() -> TestResult {
    let reg = registry()?;
    let (first, public) = key(&reg, 'a', DeviceKeyPurpose2::Static)?;
    let (alias, same) = key(&reg, 'a', DeviceKeyPurpose2::Static)?;
    assert_eq!(public, same);
    let client = KeyPair::from_secret(Zeroizing::new([3; 32]))?;
    let frame = client.seal_handshake(PublicKey::decode(&public)?, b"fixture-private")?;
    run(
        &reg,
        'a',
        DeviceOperation2::OpenHandshake {
            handle: first,
            frame: frame.clone(),
        },
    )?;
    assert!(matches!(
        run(
            &reg,
            'a',
            DeviceOperation2::OpenHandshake {
                handle: alias,
                frame
            }
        ),
        Err(Error::Replay)
    ));
    Ok(())
}
#[test]
fn failed_deadline_reservation_does_not_consume_work_capacity() -> TestResult {
    let mut cfg = config();
    cfg.max_in_flight = 1;
    let reg = Registry::new(
        cfg,
        &[registration(&"a".repeat(32)), registration(&"b".repeat(32))],
        ":1.1",
        1,
        Time {
            wall: u64::MAX - 1,
            monotonic: 0,
        },
    )?;
    let mut req = request('a', DeviceOperation2::Cancel);
    req.ttl_ms = 2;
    assert!(
        reg.reserve(
            &req,
            1,
            Time {
                wall: u64::MAX - 1,
                monotonic: 0
            }
        )
        .is_err()
    );
    req.ttl_ms = 1;
    assert!(
        reg.reserve(
            &req,
            1,
            Time {
                wall: u64::MAX - 1,
                monotonic: 0
            }
        )
        .is_ok()
    );
    Ok(())
}
fn tunnel(
    reg: &Registry,
    key: &str,
    eph: &str,
    peer: &str,
    peer_eph: &str,
    role: DeviceRole2,
) -> Result<String> {
    run(
        reg,
        'a',
        DeviceOperation2::Tunnel {
            key: key.into(),
            ephemeral: eph.into(),
            peer_static: peer.into(),
            peer_ephemeral: peer_eph.into(),
            role,
        },
    )?
    .handle
    .ok_or(Error::DeviceDenied)
}
#[test]
fn tunnel_authority_ends_when_its_parent_key_expires() -> TestResult {
    let reg = registry()?;
    let mut req = request(
        'a',
        DeviceOperation2::Key {
            purpose: DeviceKeyPurpose2::Static,
        },
    );
    req.ttl_ms = 1;
    let work = reg.reserve(&req, 1, time(0))?;
    let own = reg
        .execute(&work, &req.operation, 1, time(0))?
        .handle
        .ok_or(Error::DeviceDenied)?;
    drop(work);
    let (eph, _) = key(&reg, 'a', DeviceKeyPurpose2::Ephemeral)?;
    let peer = KeyPair::from_secret(Zeroizing::new([3; 32]))?;
    let peer_eph = KeyPair::from_secret(Zeroizing::new([4; 32]))?;
    let handle = tunnel(
        &reg,
        &own,
        &eph,
        &peer.public_key().encode(),
        &peer_eph.public_key().encode(),
        DeviceRole2::Client,
    )?;
    let req = request(
        'a',
        DeviceOperation2::Seal {
            handle,
            plaintext: vec![],
        },
    );
    let work = reg.reserve(&req, 1, time(1))?;
    assert!(reg.execute(&work, &req.operation, 1, time(1)).is_err());
    Ok(())
}
#[test]
fn revocation_fences_pending_work_but_preserves_unrelated_handles() -> TestResult {
    let reg = registry()?;
    let (revoked, _) = key(&reg, 'a', DeviceKeyPurpose2::Static)?;
    let (unrelated, _) = key(&reg, 'a', DeviceKeyPurpose2::Ephemeral)?;
    let pending = reg.reserve(&request('a', DeviceOperation2::Cancel), 1, time(0))?;
    run(&reg, 'a', DeviceOperation2::Revoke { handle: revoked })?;
    assert!(reg.validate(&pending, 1, time(0)).is_err());
    drop(pending);
    let peer = KeyPair::from_secret(Zeroizing::new([5; 32]))?;
    assert!(
        run(
            &reg,
            'a',
            DeviceOperation2::SealHandshake {
                handle: unrelated,
                peer: peer.public_key().encode(),
                plaintext: vec![]
            }
        )
        .is_ok()
    );
    Ok(())
}
