use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tinysecurity::crypto::device_pairing::{DevicePairingOwner, LegacyDeviceIdentity, Time};
type TestResult = Result<(), Box<dyn std::error::Error>>;

const SCOPE_ID: &str = "0123456789abcdef0123456789abcdef";
const FRAME_HANDLE: &str = "abcdef0123456789abcdef0123456789";

fn registry_with_frame()
-> Result<Arc<tinysecurity::crypto::device_handles::Registry>, Box<dyn std::error::Error>> {
    use tinysecurity::crypto::{device::Tunnel, device_handles::PairedTunnelRegistration};
    use tinysecurity_bus::{
        AccessTier, ApprovalScope2, DeviceConfig2, DeviceScope2, Origin, SubjectScope,
    };

    let registration = ApprovalScope2 {
        scope_id: SCOPE_ID.into(),
        subject: SubjectScope {
            user: "pairing-test-user".into(),
            workspace: "pairing-test-workspace".into(),
            agent: "pairing-test-agent".into(),
        },
        policy_ref: "pairing-test-policy".into(),
        generation: 1,
        ceiling: AccessTier::Full,
        require_approval: true,
        auto_approve_all: false,
    };
    let registry = Arc::new(tinysecurity::crypto::device_handles::Registry::new(
        DeviceConfig2 {
            scopes: vec![DeviceScope2 {
                scope_id: SCOPE_ID.into(),
                origin: Origin::Operator,
                static_secret: Some([0x61; 32]),
            }],
            max_handles: 4,
            max_in_flight: 1,
            operations_per_minute: 10,
            frames_per_minute: 10,
            max_ttl_ms: 10_000,
            max_message_bytes: 1024,
            max_bootstrap_nonces: 1,
        },
        &[registration],
        ":1.1",
        1,
        tinysecurity::crypto::device_handles::Time {
            wall: 1_000,
            monotonic: 1_000,
        },
    )?);
    let key = tinysecurity::crypto::device::KeyPair::generate()?;
    let public = key.public_key();
    let keys = key.session_keys(public, &key, public, public, public)?;
    registry.register_paired_tunnel(PairedTunnelRegistration {
        scope_id: SCOPE_ID,
        handle: FRAME_HANDLE,
        tunnel: Arc::new(std::sync::Mutex::new(Tunnel::new(
            tinysecurity::crypto::device::Role::Server,
            keys,
        ))),
        generation: 1,
        expires_wall: 5_000,
        expires_monotonic: 5_000,
        now: tinysecurity::crypto::device_handles::Time {
            wall: 1_000,
            monotonic: 1_000,
        },
    })?;
    Ok(registry)
}

fn frame_seal(registry: &tinysecurity::crypto::device_handles::Registry) -> bool {
    registry
        .execute_frame(
            &tinysecurity_bus::DeviceFrameRequest2 {
                scope_id: SCOPE_ID.into(),
                handle: FRAME_HANDLE.into(),
                call_id: "pairing-test-call".into(),
                operation: tinysecurity_bus::DeviceFrameOperation2::Seal {
                    plaintext: b"live frame".to_vec(),
                },
            },
            1,
            tinysecurity::crypto::device_handles::Time {
                wall: 1_001,
                monotonic: 1_001,
            },
        )
        .is_ok()
}

fn owner() -> Result<DevicePairingOwner, Box<dyn std::error::Error>> {
    let config = tinysecurity_bus::DevicePairingConfig2 {
        scopes: vec![tinysecurity_bus::DevicePairingScope2 {
            scope_id: "0123456789abcdef0123456789abcdef".into(),
            secret_registration_id: "abcdef0123456789abcdef0123456789".into(),
            persistence_backend_id: "user-secret-store".into(),
            legacy_device_backend_id: None,
            legacy_source_registration_id: None,
        }],
        max_pairings: 1,
        max_pending: 1,
        max_pending_ttl_ms: 1_000,
        max_session_ttl_ms: 1_000,
        max_state_bytes: 4096,
        callback_timeout_ms: 1000,
    };
    Ok(DevicePairingOwner::new(
        config,
        1,
        Time {
            wall: 1000,
            monotonic: 1000,
        },
        [(
            "0123456789abcdef0123456789abcdef".into(),
            zeroize::Zeroizing::new([0x41; 32]),
        )]
        .into(),
    )?)
}

fn controller(channel: &str) -> tinysecurity_bus::DevicePairingContextResponse2 {
    tinysecurity_bus::DevicePairingContextResponse2 {
        scope_id: "0123456789abcdef0123456789abcdef".into(),
        user_binding: "pairing-test-user".into(),
        secret_master_handle: None,
        legacy_import_handle: None,
        channel_id: channel.into(),
        connection_nonce: "pairing-test-nonce".into(),
        generation: 1,
        source: tinysecurity_bus::DevicePairingSource2::AuthenticatedUserController,
        expires_at_ms: 10_000,
    }
}

fn import_one(
    owner: &mut DevicePairingOwner,
    channel: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    Ok(owner.import_legacy_identities(
        &controller(channel),
        vec![LegacyDeviceIdentity {
            channel_id: channel.into(),
            device_public_key: tinysecurity::crypto::device::KeyPair::generate()?
                .public_key()
                .encode(),
            core_private_key: zeroize::Zeroizing::new([0x52; 32]),
            revoked: false,
        }],
        Time {
            wall: 1000,
            monotonic: 1000,
        },
    )?[0]
        .pairing_id
        .clone())
}

#[tokio::test]
async fn canceled_revoke_callback_faults_the_mutated_owner() -> TestResult {
    let mut owner = owner()?;
    let pairing_id = import_one(&mut owner, "channel-revoke")?;
    let faulted = Arc::new(AtomicBool::new(false));
    let task_faulted = Arc::clone(&faulted);
    let callback_started = Arc::new(tokio::sync::Notify::new());
    let started = Arc::clone(&callback_started);
    let committed = Arc::new(AtomicBool::new(false));
    let cas_committed = Arc::clone(&committed);
    let context = controller("channel-revoke");
    let registry = registry_with_frame()?;
    let notified = callback_started.notified();
    tokio::pin!(notified);
    let mut operation = Box::pin(revoke_and_persist(
        &mut owner,
        PersistenceContext {
            faulted: task_faulted,
            registry,
            scope_id: SCOPE_ID.into(),
        },
        &pairing_id,
        &context,
        Time {
            wall: 1001,
            monotonic: 1001,
        },
        || Ok(()),
        move |_snapshot| async move {
            cas_committed.store(true, Ordering::Release);
            started.notify_one();
            std::future::pending::<tinybus::Result<String>>().await
        },
    ));
    tokio::select! {
        () = &mut notified => {},
        result = &mut operation => panic!("revoke unexpectedly completed: {result:?}"),
    }
    drop(operation);
    assert!(committed.load(Ordering::Acquire));
    assert!(check_persistence_fault(&mut owner, &faulted).is_err());
    assert!(
        owner
            .recover_channel(
                "channel-revoke",
                &controller("channel-revoke"),
                Time {
                    wall: 1002,
                    monotonic: 1002,
                },
            )
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn canceled_confirmation_persistence_retires_existing_frame_handles() -> TestResult {
    let registry = registry_with_frame()?;
    assert!(frame_seal(&registry));
    let faulted = Arc::new(AtomicBool::new(false));
    let callback_started = Arc::new(tokio::sync::Notify::new());
    let started = Arc::clone(&callback_started);
    let notified = callback_started.notified();
    tokio::pin!(notified);
    let mut operation = Box::pin(persist_fenced(
        PersistenceContext {
            faulted: Arc::clone(&faulted),
            registry: Arc::clone(&registry),
            scope_id: SCOPE_ID.into(),
        },
        async move {
            started.notify_one();
            std::future::pending::<tinybus::Result<()>>().await
        },
    ));
    tokio::select! {
        () = &mut notified => {},
        result = &mut operation => panic!("persistence unexpectedly completed: {result:?}"),
    }
    drop(operation);
    assert!(faulted.load(Ordering::Acquire));
    assert!(!frame_seal(&registry));
    Ok(())
}

#[tokio::test]
async fn successful_revoke_persistence_keeps_owner_usable() -> TestResult {
    let mut owner = owner()?;
    let pairing_id = import_one(&mut owner, "channel-revoke-success")?;
    let faulted = Arc::new(AtomicBool::new(false));
    let registry = registry_with_frame()?;
    revoke_and_persist(
        &mut owner,
        PersistenceContext {
            faulted: Arc::clone(&faulted),
            registry: Arc::clone(&registry),
            scope_id: SCOPE_ID.into(),
        },
        &pairing_id,
        &controller("channel-revoke-success"),
        Time {
            wall: 1001,
            monotonic: 1001,
        },
        || Ok(()),
        |_snapshot| async { Ok("revision-2".into()) },
    )
    .await?;
    check_persistence_fault(&mut owner, &faulted)?;
    assert!(frame_seal(&registry));
    assert!(
        owner
            .public_key(
                "0123456789abcdef0123456789abcdef",
                Time {
                    wall: 1002,
                    monotonic: 1002,
                },
            )
            .is_ok()
    );
    Ok(())
}

#[tokio::test]
async fn denied_revoke_does_not_fault_the_pairing_owner() -> TestResult {
    let mut owner = owner()?;
    import_one(&mut owner, "channel-revoke-denied")?;
    let faulted = Arc::new(AtomicBool::new(false));
    let result = revoke_and_persist(
        &mut owner,
        PersistenceContext {
            faulted: Arc::clone(&faulted),
            registry: registry_with_frame()?,
            scope_id: SCOPE_ID.into(),
        },
        "unknown-pairing",
        &controller("channel-revoke-denied"),
        Time {
            wall: 1001,
            monotonic: 1001,
        },
        || Ok(()),
        |_snapshot| async { Ok("unreachable-revision".into()) },
    )
    .await;
    assert!(result.is_err(), "unknown pairing ids must be denied");

    fail_revoke_owner_on_error(&mut owner, &faulted);

    assert!(
        owner
            .public_key(
                SCOPE_ID,
                Time {
                    wall: 1002,
                    monotonic: 1002,
                },
            )
            .is_ok(),
        "a denied revoke before persistence must leave the owner usable"
    );
    Ok(())
}

#[tokio::test]
async fn canceled_legacy_import_callback_faults_the_mutated_owner() -> TestResult {
    let mut owner = owner()?;
    let faulted = Arc::new(AtomicBool::new(false));
    let task_faulted = Arc::clone(&faulted);
    let callback_started = Arc::new(tokio::sync::Notify::new());
    let started = Arc::clone(&callback_started);
    let imported_cas_committed = Arc::new(AtomicBool::new(false));
    let cas_committed = Arc::clone(&imported_cas_committed);
    let context = controller("channel-import");
    let identities = vec![LegacyDeviceIdentity {
        channel_id: "channel-import".into(),
        device_public_key: tinysecurity::crypto::device::KeyPair::generate()?
            .public_key()
            .encode(),
        core_private_key: zeroize::Zeroizing::new([0x53; 32]),
        revoked: false,
    }];
    let notified = callback_started.notified();
    tokio::pin!(notified);
    let mut operation = Box::pin(import_legacy_and_persist(
        &mut owner,
        PersistenceContext {
            faulted: task_faulted,
            registry: registry_with_frame()?,
            scope_id: SCOPE_ID.into(),
        },
        &context,
        identities,
        Time {
            wall: 1000,
            monotonic: 1000,
        },
        move |_snapshot| async move {
            cas_committed.store(true, Ordering::Release);
            started.notify_one();
            std::future::pending::<tinybus::Result<String>>().await
        },
    ));
    tokio::select! {
        () = &mut notified => {},
        result = &mut operation => panic!("legacy import unexpectedly completed: {result:?}"),
    }
    drop(operation);
    assert!(imported_cas_committed.load(Ordering::Acquire));
    assert!(check_persistence_fault(&mut owner, &faulted).is_err());
    assert!(
        owner
            .recover_channel(
                "channel-import",
                &context,
                Time {
                    wall: 1001,
                    monotonic: 1001,
                },
            )
            .is_err()
    );
    Ok(())
}
