//! Actual hashed native device dispatch, confidential routing and verified callbacks.
#[path = "device_native_contract/fixture.rs"]
mod fixture;
#[path = "approval_native_contract/namespace.rs"]
mod namespace;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tinybus::{Connection, broker::Broker, module::ModuleHost, transport::memory::MemoryBus};
use tinysecurity_bus::*;
#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let library = std::path::PathBuf::from(
        std::env::args()
            .nth(1)
            .ok_or("usage: device_native_contract <library>")?,
    )
    .canonicalize()?;
    let hash = tinybus::module::sha256_file(&library)?;
    let name = library
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("fixture library name")?;
    std::fs::write(
        library
            .parent()
            .ok_or("fixture library parent")?
            .join("modules.toml"),
        format!("\"{name}\" = \"{hash}\"\n"),
    )?;
    let (_directory, root) = namespace::create()?;
    let bus = MemoryBus::new();
    let broker = Broker::new();
    let task = broker.spawn(bus.clone());
    let lifecycle = ModuleHost::new(broker);
    let host = Connection::connect(bus.connect().await?).await?;
    let mut configuration = ModuleConfig {
        device: Some(fixture::device_config()),
        trusted_host: host.unique_name().map(|n| n.to_string()),
        approvals: Some(ApprovalConfig2 {
            timeout_ms: 30_000,
            scopes: vec![fixture::registration()],
        }),
        audit: Some(fixture::audit_config(Some(
            root.join("audit").to_str().ok_or("fixture path")?.into(),
        ))),
        ..Default::default()
    };
    let loaded =
        lifecycle.load_file_with_config(&library, serde_json::to_value(&configuration)?)?;
    let module = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(peer) = host.name_owner(names::INTERFACE).await? {
                break tinybus::Result::Ok(peer);
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    let store = Arc::new(Mutex::new(fixture::store::DiskStore::open(
        &root.join("approvals.journal"),
    )?));
    fixture::serve_callbacks(&host, &module, &store, true).await?;
    let proxy = host
        .proxy(module.as_str(), names::OBJECT_PATH, names::INTERFACE)?
        .with_timeout(Duration::from_secs(10));
    assert!(proxy.attestation().await?.is_some());
    let info: PolicyInfo = proxy.call(names::methods::POLICY_INFO, ()).await?;
    assert!(
        info.capabilities
            .contains(&names::methods::EXECUTE_DEVICE2.to_owned())
    );
    assert!(!serde_json::to_string(&info)?.contains("static_secret"));
    let rejected = EvaluateDeviceRequest2 {
        request: fixture::request(1, DeviceOperation2::Cancel),
        audit: fixture::audit(1),
    };
    assert!(
        proxy
            .call::<ApprovalRow2>(names::methods::EVALUATE_DEVICE2, (rejected.clone(),))
            .await
            .is_err()
    );
    let attacker = Connection::connect(bus.connect().await?).await?;
    assert!(
        attacker
            .proxy(module.as_str(), names::OBJECT_PATH, names::INTERFACE)?
            .call_confidential::<ApprovalRow2>(names::methods::EVALUATE_DEVICE2, (rejected,))
            .await
            .is_err()
    );
    let malformed = serde_json::json!([{"request":{"scope_id":"a","call_id":"private-secret","ttl_ms":1,"operation":{"kind":"seal","handle":"private-secret","plaintext":"private-secret"}},"audit":fixture::audit(1)}]);
    let error = proxy
        .call_confidential::<ApprovalRow2>(names::methods::EVALUATE_DEVICE2, malformed)
        .await
        .err()
        .ok_or("fixture malformed call accepted")?;
    assert!(!error.to_string().contains("private-secret"));
    let mut sequence = 1;
    let server = fixture::run(
        &proxy,
        &store,
        &mut sequence,
        DeviceOperation2::Key {
            purpose: DeviceKeyPurpose2::Static,
        },
    )
    .await?;
    let client = fixture::run(
        &proxy,
        &store,
        &mut sequence,
        DeviceOperation2::Key {
            purpose: DeviceKeyPurpose2::Ephemeral,
        },
    )
    .await?;
    let core_public = server.public_key.ok_or("fixture public")?;
    let server = server.handle.ok_or("fixture handle")?;
    let client_public = client.public_key.ok_or("fixture public")?;
    let client = client.handle.ok_or("fixture handle")?;
    let handshake = fixture::run(
        &proxy,
        &store,
        &mut sequence,
        DeviceOperation2::SealHandshake {
            handle: client.clone(),
            peer: core_public.clone(),
            plaintext: b"private-secret".to_vec(),
        },
    )
    .await?
    .bytes;
    let opened = fixture::run(
        &proxy,
        &store,
        &mut sequence,
        DeviceOperation2::OpenHandshake {
            handle: server.clone(),
            frame: handshake.clone(),
        },
    )
    .await?;
    assert_eq!(opened.bytes, b"private-secret");
    assert_eq!(opened.public_key, Some(client_public.clone()));
    assert!(
        fixture::run(
            &proxy,
            &store,
            &mut sequence,
            DeviceOperation2::OpenHandshake {
                handle: server.clone(),
                frame: handshake
            }
        )
        .await
        .is_err()
    );
    let ack = fixture::run(
        &proxy,
        &store,
        &mut sequence,
        DeviceOperation2::SealAck {
            handle: server.clone(),
            peer: client_public,
            plaintext: b"ack".to_vec(),
        },
    )
    .await?
    .bytes;
    assert_eq!(
        fixture::run(
            &proxy,
            &store,
            &mut sequence,
            DeviceOperation2::OpenAck {
                handle: client,
                peer: core_public.clone(),
                frame: ack
            }
        )
        .await?
        .bytes,
        b"ack"
    );
    native_tunnel(&proxy, &store, &mut sequence, &server, &core_public).await?;
    fixture::run(
        &proxy,
        &store,
        &mut sequence,
        DeviceOperation2::Revoke {
            handle: server.clone(),
        },
    )
    .await?;
    assert!(
        fixture::run(
            &proxy,
            &store,
            &mut sequence,
            DeviceOperation2::OpenHandshake {
                handle: server,
                frame: vec![3; 73]
            }
        )
        .await
        .is_err()
    );
    let key = fixture::run(
        &proxy,
        &store,
        &mut sequence,
        DeviceOperation2::Key {
            purpose: DeviceKeyPurpose2::Static,
        },
    )
    .await?
    .handle
    .ok_or("fixture handle")?;
    // Actual SDK reinit retains the callback peer/registrations while advancing generation.
    for scope in &mut configuration
        .device
        .as_mut()
        .ok_or("fixture config")?
        .scopes
    {
        scope.static_secret = None;
    }
    configuration
        .device
        .as_mut()
        .ok_or("fixture config")?
        .max_handles = 16;
    lifecycle
        .reinitialize(&loaded.name, serde_json::to_value(configuration)?)
        .await?;
    // Valid new-generation approval/audit receipts cannot revive the old handle.
    assert!(
        fixture::run_at(
            &proxy,
            &store,
            &mut sequence,
            DeviceOperation2::Revoke { handle: key },
            2
        )
        .await
        .is_err()
    );
    let current = fixture::run_at(
        &proxy,
        &store,
        &mut sequence,
        DeviceOperation2::Key {
            purpose: DeviceKeyPurpose2::Static,
        },
        2,
    )
    .await?;
    let observer = current.handle.ok_or("fixture handle")?;
    let after: PolicyInfo = proxy.call(names::methods::POLICY_INFO, ()).await?;
    assert_eq!(after.generation, 2);
    let journal = std::fs::read(root.join("approvals.journal"))?;
    assert!(!String::from_utf8_lossy(&journal).contains("private-secret"));
    let audit = std::fs::read(root.join("audit.journal"))?;
    assert!(!audit.is_empty());
    assert!(!String::from_utf8_lossy(&audit).contains("private-secret"));
    lifecycle.shutdown(Duration::from_secs(5)).await;
    assert!(
        proxy
            .call::<PolicyInfo>(names::methods::POLICY_INFO, ())
            .await
            .is_err()
    );
    let mut correlation = fixture::audit(sequence);
    correlation.generation = 2;
    assert!(
        proxy
            .call_confidential::<DeviceResponse2>(
                names::methods::EXECUTE_DEVICE2,
                (ExecuteDeviceRequest2 {
                    request: fixture::request(
                        sequence,
                        DeviceOperation2::Revoke { handle: observer }
                    ),
                    request_id: "f".repeat(32),
                    audit: correlation
                },)
            )
            .await
            .is_err()
    );
    task.abort();
    assert_eq!(hash, tinybus::module::sha256_file(&library)?);
    println!(
        "native device: SHA256={hash}; verified peer + confidential RPCs + exact human/audit receipts + v2/v3/v4 + replay/revoke/reinit/shutdown passed"
    );
    Ok(())
}
async fn native_tunnel(
    proxy: &tinybus::Proxy,
    store: &Arc<Mutex<fixture::store::DiskStore>>,
    sequence: &mut u64,
    own: &str,
    public: &str,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    use tinysecurity::crypto::device::{KeyPair, PublicKey, Role, Tunnel};
    let ephemeral = fixture::run(
        proxy,
        store,
        sequence,
        DeviceOperation2::Key {
            purpose: DeviceKeyPurpose2::Ephemeral,
        },
    )
    .await?;
    let ephemeral_public = PublicKey::decode(&ephemeral.public_key.ok_or("fixture public")?)?;
    let peer = KeyPair::generate()?;
    let peer_ephemeral = KeyPair::generate()?;
    let keys = peer.session_keys(
        PublicKey::decode(public)?,
        &peer_ephemeral,
        ephemeral_public,
        ephemeral_public,
        peer_ephemeral.public_key(),
    )?;
    let mut peer_tunnel = Tunnel::new(Role::Server, keys);
    let tunnel = fixture::run(
        proxy,
        store,
        sequence,
        DeviceOperation2::Tunnel {
            key: own.into(),
            ephemeral: ephemeral.handle.ok_or("fixture ephemeral")?,
            peer_static: peer.public_key().encode(),
            peer_ephemeral: peer_ephemeral.public_key().encode(),
            role: DeviceRole2::Client,
        },
    )
    .await?
    .handle
    .ok_or("fixture tunnel")?;
    let outgoing = fixture::run(
        proxy,
        store,
        sequence,
        DeviceOperation2::Seal {
            handle: tunnel.clone(),
            plaintext: b"private-secret".to_vec(),
        },
    )
    .await?
    .bytes;
    assert_eq!(&*peer_tunnel.open(&outgoing)?, b"private-secret");
    let incoming = peer_tunnel.seal(b"private-secret")?;
    assert_eq!(
        fixture::run(
            proxy,
            store,
            sequence,
            DeviceOperation2::Open {
                handle: tunnel.clone(),
                frame: incoming.clone()
            }
        )
        .await?
        .bytes,
        b"private-secret"
    );
    assert!(
        fixture::run(
            proxy,
            store,
            sequence,
            DeviceOperation2::Open {
                handle: tunnel,
                frame: incoming
            }
        )
        .await
        .is_err()
    );
    Ok(())
}
