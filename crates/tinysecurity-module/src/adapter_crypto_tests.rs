use super::*;
use tinysecurity_bus::names;

fn initialization(connection: &tinybus::Connection, peer: &str) -> Initialization<'static> {
    // The connection outlives each test body; leak a clone for a 'static borrow.
    let leaked: &'static tinybus::Connection = Box::leak(Box::new(connection.clone()));
    let _ = peer;
    Initialization {
        connection: leaked,
        peer: None,
        generation: 1,
        clock: Arc::new(tinysecurity::approval::SystemClock::default()),
    }
}

struct Fixture {
    service: PolicyService,
    host: tinybus::Connection,
    module: tinybus::Connection,
    broker: tokio::task::AbortHandle,
    dir: std::path::PathBuf,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.broker.abort();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[derive(Clone)]
struct Consenter {
    allow: Arc<std::sync::atomic::AtomicBool>,
    seen: Arc<Mutex<Vec<KeyringConsentRequest2>>>,
}
#[tinybus::interface(name = "ai.tinyhumans.tinysecurity.KeyringConsent2")]
impl Consenter {
    async fn consent(
        &self,
        request: KeyringConsentRequest2,
    ) -> tinybus::Result<KeyringConsentResponse2> {
        // The prompt carries the secret name but never a value.
        assert!(!serde_json::to_string(&request)?.contains("private-value"));
        self.seen.lock().map_err(|_| denied())?.push(request);
        std::future::ready(Ok(KeyringConsentResponse2 {
            allowed: self.allow.load(std::sync::atomic::Ordering::SeqCst),
        }))
        .await
    }
}

fn config(dir: &std::path::Path) -> CryptoConfig2 {
    CryptoConfig2 {
        max_payload_bytes: 4096,
        operations_per_minute: 50,
        keyring: Some(tinysecurity_bus::KeyringConfig2 {
            service: "tinysecurity-test".into(),
            backend: KeyringBackend2::EncryptedFile {
                directory: dir.to_string_lossy().into_owned(),
            },
            consent_timeout_ms: 1000,
        }),
        pairing: Some(tinysecurity_bus::PairingConfig2 {
            accounts: vec![
                tinysecurity_bus::PairingAccount2 {
                    scope: "scope".into(),
                    provider: "telegram".into(),
                    account: "acct".into(),
                    lifecycle: "live".into(),
                    require_pairing: true,
                    tokens: vec!["legacy-bearer".into()],
                },
                tinysecurity_bus::PairingAccount2 {
                    scope: "scope".into(),
                    provider: "telegram".into(),
                    account: "fresh".into(),
                    lifecycle: "live".into(),
                    require_pairing: true,
                    tokens: vec![],
                },
            ],
            in_flight: 2,
            rate: 100,
        }),
    }
}

async fn fixture(allow: bool) -> Result<(Fixture, Consenter), Box<dyn std::error::Error>> {
    use tinybus::{Connection, broker::Broker, transport::memory::MemoryBus};
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone()).abort_handle();
    let host = Connection::connect(bus.connect().await?).await?;
    let module = Connection::connect(bus.connect().await?).await?;
    let host_peer = host.unique_name().ok_or("host")?;
    let dir = std::env::temp_dir()
        .canonicalize()?
        .join(format!("tinysecurity-crypto-{}", std::process::id()));
    let dir = dir.join(format!("{:x}", std::ptr::addr_of!(bus) as usize));
    std::fs::create_dir_all(&dir)?;
    let mut init = initialization(&module, host_peer.as_str());
    init.peer = Some(Box::leak(host_peer.as_str().to_owned().into_boxed_str()));
    let state = configure(Some(config(&dir)), None, &init)?.ok_or("state")?;
    let mut service = super::super::service_for(
        Arc::new(std::sync::RwLock::new(tinysecurity::Policy::new(
            tinysecurity_bus::ModuleConfig::default(),
        )?)),
        None,
    );
    service.crypto = Some(state);
    let consenter = Consenter {
        allow: Arc::new(std::sync::atomic::AtomicBool::new(allow)),
        seen: Arc::default(),
    };
    let module_peer = module.unique_name().ok_or("module")?;
    host.serve_at(
        callback_names2::OBJECT_PATH.parse()?,
        crate::callbacks::Authenticated::new(
            consenter.clone(),
            crate::callbacks::PeerBinding::new(Some(module_peer.as_str()))?,
        ),
    )
    .await?;
    Ok((
        Fixture {
            service,
            host,
            module,
            broker,
            dir,
        },
        consenter,
    ))
}

fn caller() -> tinysecurity_bus::CallerContext {
    tinysecurity_bus::CallerContext {
        agent: "agent".into(),
        call_id: "call".into(),
        ..Default::default()
    }
}
fn keyring_request(operation: KeyringOperation2) -> KeyringRequest2 {
    KeyringRequest2 {
        caller: caller(),
        purpose: "store a token".into(),
        operation,
    }
}

#[tokio::test]
async fn unconfigured_service_denies_every_member() -> Result<(), Box<dyn std::error::Error>> {
    let service = super::super::service_for(
        Arc::new(std::sync::RwLock::new(tinysecurity::Policy::new(
            tinysecurity_bus::ModuleConfig::default(),
        )?)),
        None,
    );
    assert!(
        service
            .password_crypt(PasswordRequest2 {
                operation: PasswordOperation2::Encrypt {
                    password: "p".into(),
                    plaintext: vec![],
                    salt: None
                }
            })
            .await
            .is_err()
    );
    assert!(
        service
            .keyring_access(keyring_request(KeyringOperation2::Get {
                name: "a:b".into()
            }))
            .await
            .is_err()
    );
    assert!(
        service
            .pairing_control(PairingRequest2 {
                account: "a".into(),
                operation: PairingOperation2::Status
            })
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn password_round_trip_and_wrong_password_and_bounds()
-> Result<(), Box<dyn std::error::Error>> {
    let (fixture, _) = fixture(true).await?;
    let sealed = fixture
        .service
        .password_crypt(PasswordRequest2 {
            operation: PasswordOperation2::Encrypt {
                password: "correct horse".into(),
                plaintext: b"payload".to_vec(),
                salt: None,
            },
        })
        .await?
        .payload
        .ok_or("payload")?;
    assert_eq!(sealed.salt.len(), 16);
    let open = |password: &str, payload: PasswordPayload2| PasswordRequest2 {
        operation: PasswordOperation2::Decrypt {
            password: password.into(),
            payload,
        },
    };
    let opened = fixture
        .service
        .password_crypt(open("correct horse", sealed.clone()))
        .await?;
    assert_eq!(opened.bytes, b"payload");
    assert!(
        fixture
            .service
            .password_crypt(open("wrong", sealed))
            .await
            .is_err()
    );
    // Plaintext above the configured bound is rejected before derivation.
    assert!(
        fixture
            .service
            .password_crypt(PasswordRequest2 {
                operation: PasswordOperation2::Encrypt {
                    password: "p".into(),
                    plaintext: vec![0; 4097],
                    salt: None
                }
            })
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn password_opens_the_frozen_host_fixture() -> Result<(), Box<dyn std::error::Error>> {
    let (fixture, _) = fixture(true).await?;
    let data: serde_json::Value = serde_json::from_str(include_str!(
        "../../tinysecurity-crypto/fixtures/openhuman-password.json"
    ))?;
    let mut payload: PasswordPayload2 = serde_json::from_value(data["payload"].clone())?;
    payload.salt = serde_json::from_value(data["salt"].clone())?;
    let opened = fixture
        .service
        .password_crypt(PasswordRequest2 {
            operation: PasswordOperation2::Decrypt {
                password: data["password"].as_str().ok_or("password")?.into(),
                payload,
            },
        })
        .await?;
    assert_eq!(opened.bytes, b"host AES/password fixture\0legacy bytes");
    Ok(())
}

#[tokio::test]
async fn keyring_requires_consent_for_each_operation() -> Result<(), Box<dyn std::error::Error>> {
    let (fixture, consenter) = fixture(true).await?;
    let name = "user:token";
    fixture
        .service
        .keyring_access(keyring_request(KeyringOperation2::Set {
            name: name.into(),
            value: b"private-value".to_vec(),
        }))
        .await?;
    let got = fixture
        .service
        .keyring_access(keyring_request(KeyringOperation2::Get {
            name: name.into(),
        }))
        .await?;
    assert!(got.found);
    assert_eq!(got.bytes, b"private-value");
    {
        let seen = consenter.seen.lock().map_err(|_| "seen")?;
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].access, KeyringAccess2::Write);
        assert_eq!(seen[1].access, KeyringAccess2::Read);
        assert_eq!(seen[0].name, name);
    }
    // Consent withdrawn: nothing is read, written or deleted.
    consenter
        .allow
        .store(false, std::sync::atomic::Ordering::SeqCst);
    for operation in [
        KeyringOperation2::Get { name: name.into() },
        KeyringOperation2::Set {
            name: name.into(),
            value: b"x".to_vec(),
        },
        KeyringOperation2::Delete { name: name.into() },
    ] {
        assert!(
            fixture
                .service
                .keyring_access(keyring_request(operation))
                .await
                .is_err()
        );
    }
    consenter
        .allow
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let still = fixture
        .service
        .keyring_access(keyring_request(KeyringOperation2::Get {
            name: name.into(),
        }))
        .await?;
    assert_eq!(still.bytes, b"private-value");
    let removed = fixture
        .service
        .keyring_access(keyring_request(KeyringOperation2::Delete {
            name: name.into(),
        }))
        .await?;
    assert!(removed.found);
    let gone = fixture
        .service
        .keyring_access(keyring_request(KeyringOperation2::Get {
            name: name.into(),
        }))
        .await?;
    assert!(!gone.found);
    assert!(fixture.host.unique_name().is_some() && fixture.module.unique_name().is_some());
    Ok(())
}

#[tokio::test]
async fn keyring_rejects_bad_names_purposes_and_oversized_values()
-> Result<(), Box<dyn std::error::Error>> {
    let (fixture, consenter) = fixture(true).await?;
    let ok_name = "user:ok";
    let mut bad_purpose = keyring_request(KeyringOperation2::Get {
        name: ok_name.into(),
    });
    bad_purpose.purpose = "line\nbreak".into();
    assert!(fixture.service.keyring_access(bad_purpose).await.is_err());
    assert!(
        fixture
            .service
            .keyring_access(keyring_request(KeyringOperation2::Get {
                name: "control\u{7}char".into()
            }))
            .await
            .is_err()
    );
    assert!(
        fixture
            .service
            .keyring_access(keyring_request(KeyringOperation2::Set {
                name: ok_name.into(),
                value: vec![0; 4097]
            }))
            .await
            .is_err()
    );
    // Rejected requests never reach the human.
    assert!(consenter.seen.lock().map_err(|_| "seen")?.is_empty());
    Ok(())
}

#[tokio::test]
async fn pairing_authenticates_constant_time_and_revokes() -> Result<(), Box<dyn std::error::Error>>
{
    let (fixture, _) = fixture(true).await?;
    let call = |operation| PairingRequest2 {
        account: "acct".into(),
        operation,
    };
    let status = fixture
        .service
        .pairing_control(call(PairingOperation2::Status))?;
    assert!(status.is_paired && status.require_pairing && !status.active);
    let ok = fixture
        .service
        .pairing_control(call(PairingOperation2::Authenticate {
            bearer: "legacy-bearer".into(),
        }))?;
    assert_eq!(ok.authenticated, Some(true));
    let bad = fixture
        .service
        .pairing_control(call(PairingOperation2::Authenticate {
            bearer: "other".into(),
        }))?;
    assert_eq!(bad.authenticated, Some(false));
    assert!(format!("{bad:?}").find("legacy-bearer").is_none());
    assert!(
        fixture
            .service
            .pairing_control(PairingRequest2 {
                account: "unregistered".into(),
                operation: PairingOperation2::Status
            })
            .is_err()
    );
    let revoked = fixture
        .service
        .pairing_control(call(PairingOperation2::Revoke))?;
    assert!(revoked.require_pairing && !revoked.is_paired && !revoked.active);
    // Revoked authority never authenticates again, and the fence is reported as unpaired.
    assert!(
        fixture
            .service
            .pairing_control(call(PairingOperation2::Authenticate {
                bearer: "legacy-bearer".into(),
            }))
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn operation_rate_is_bounded_per_minute() -> Result<(), Box<dyn std::error::Error>> {
    let (fixture, _) = fixture(true).await?;
    let state = fixture.service.crypto.as_ref().ok_or("state")?;
    let limit = state.config.operations_per_minute;
    let call = || PairingRequest2 {
        account: "acct".into(),
        operation: PairingOperation2::Status,
    };
    let mut allowed = 0;
    for _ in 0..(limit + 5) {
        if fixture.service.pairing_control(call()).is_ok() {
            allowed += 1;
        }
    }
    // The clock's minute may roll once during the loop; never more than two windows.
    assert!((limit..=limit * 2).contains(&allowed));
    Ok(())
}

#[test]
fn configuration_bounds_are_enforced() {
    let dir = std::env::temp_dir();
    let mut bad = config(&dir);
    bad.max_payload_bytes = 0;
    assert!(validate(&bad).is_err());
    let mut bad = config(&dir);
    bad.operations_per_minute = 4097;
    assert!(validate(&bad).is_err());
    let mut bad = config(&dir);
    if let Some(keyring) = &mut bad.keyring {
        keyring.consent_timeout_ms = 300_001;
    }
    assert!(validate(&bad).is_err());
    let mut bad = config(&dir);
    if let Some(pairing) = &mut bad.pairing {
        pairing.in_flight = 0;
    }
    assert!(validate(&bad).is_err());
    assert!(validate(&config(&dir)).is_ok());
}

#[tokio::test]
async fn members_require_confidential_transport_and_the_authenticated_peer()
-> Result<(), Box<dyn std::error::Error>> {
    use tinybus::Interface;
    let (fixture, _) = fixture(true).await?;
    for name in [
        names::methods::PASSWORD_CRYPT2,
        names::methods::KEYRING_ACCESS2,
        names::methods::PAIRING_CONTROL2,
    ] {
        let member: tinybus::MemberName = name.parse()?;
        assert!(fixture.service.requires_confidential(&member));
        assert!(names::METHODS.contains(&name));
    }
    // A caller other than the bound host cannot reach the members at all.
    let host_peer = fixture.host.unique_name().ok_or("host")?;
    let authenticated = crate::callbacks::Authenticated::new(
        fixture.service.clone(),
        crate::callbacks::PeerBinding::new(Some(host_peer.as_str()))?,
    );
    let member: tinybus::MemberName = names::methods::PASSWORD_CRYPT2.parse()?;
    let error = authenticated
        .call(&member, serde_json::json!(["private-secret"]))
        .await
        .err()
        .ok_or("must deny")?;
    assert!(!error.to_string().contains("private-secret"));
    Ok(())
}

#[derive(Debug, Default)]
struct StepClock(std::sync::atomic::AtomicU64);
impl tinysecurity::approval::Clock for StepClock {
    fn wall_ms(&self) -> Option<u64> {
        Some(1_000 + self.0.load(std::sync::atomic::Ordering::SeqCst))
    }
    fn monotonic_ms(&self) -> u64 {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

async fn standalone(
    config: CryptoConfig2,
    clock: Arc<dyn tinysecurity::approval::Clock>,
) -> Result<
    (
        Arc<CryptoState>,
        tinybus::Connection,
        Initialization<'static>,
    ),
    Box<dyn std::error::Error>,
> {
    use tinybus::{Connection, broker::Broker, transport::memory::MemoryBus};
    let bus = MemoryBus::new();
    let _ = Broker::new().spawn(bus.clone());
    let connection = Connection::connect(bus.connect().await?).await?;
    let peer = connection.unique_name().ok_or("peer")?;
    let leaked: &'static Connection = Box::leak(Box::new(connection.clone()));
    let init = Initialization {
        connection: leaked,
        peer: Some(Box::leak(peer.as_str().to_owned().into_boxed_str())),
        generation: 1,
        clock,
    };
    let state = configure(Some(config), None, &init)?.ok_or("state")?;
    Ok((state, connection, init))
}

fn bare_config() -> CryptoConfig2 {
    CryptoConfig2 {
        max_payload_bytes: 64,
        operations_per_minute: 1,
        keyring: None,
        pairing: None,
    }
}

#[tokio::test]
async fn immutable_reinit_accepts_same_or_absent_config_and_rejects_changes()
-> Result<(), Box<dyn std::error::Error>> {
    let clock: Arc<dyn tinysecurity::approval::Clock> = Arc::new(StepClock::default());
    let (state, _connection, init) = standalone(bare_config(), clock).await?;
    let current = Some(Arc::downgrade(&state));
    let same = configure(Some(bare_config()), Some(&current), &init)?;
    assert!(same.is_some_and(|same| Arc::ptr_eq(&same, &state)));
    assert!(configure(None, Some(&current), &init)?.is_some());
    let mut changed = bare_config();
    changed.max_payload_bytes = 65;
    assert!(configure(Some(changed), Some(&current), &init).is_err());
    // A module first initialized without crypto cannot gain it on reinit.
    assert!(configure(None, Some(&None), &init)?.is_none());
    assert!(configure(Some(bare_config()), Some(&None), &init).is_err());
    // A dropped owner (runtime shutdown) never resurrects.
    drop(state);
    assert!(configure(None, Some(&current), &init).is_err());
    Ok(())
}

#[tokio::test]
async fn initialization_requires_a_unique_authenticated_peer_and_valid_backends()
-> Result<(), Box<dyn std::error::Error>> {
    let clock: Arc<dyn tinysecurity::approval::Clock> = Arc::new(StepClock::default());
    let (_state, connection, mut init) = standalone(bare_config(), clock.clone()).await?;
    init.peer = None;
    assert!(configure(Some(bare_config()), None, &init).is_err());
    init.peer = Some("well.known");
    assert!(configure(Some(bare_config()), None, &init).is_err());
    let peer = connection.unique_name().ok_or("peer")?;
    init.peer = Some(Box::leak(peer.as_str().to_owned().into_boxed_str()));
    let dir = std::env::temp_dir().canonicalize()?;
    for backend in [KeyringBackend2::Os, KeyringBackend2::LinuxKernel] {
        let mut config = config(&dir);
        config.pairing = None;
        if let Some(keyring) = &mut config.keyring {
            keyring.backend = backend;
        }
        // Lazy OS stores construct without touching the credential store.
        let built = configure(Some(config), None, &init);
        assert!(built.is_ok() || !cfg!(target_os = "linux"));
    }
    let mut config = config(&dir);
    if let Some(keyring) = &mut config.keyring {
        keyring.backend = KeyringBackend2::SecretService;
    }
    assert!(configure(Some(config), None, &init).is_err());
    let mut relative = self::config(&dir);
    if let Some(keyring) = &mut relative.keyring {
        keyring.backend = KeyringBackend2::EncryptedFile {
            directory: "relative".into(),
        };
    }
    assert!(configure(Some(relative), None, &init).is_err());
    Ok(())
}

#[tokio::test]
async fn activation_is_single_shot_and_the_rate_window_rolls_over()
-> Result<(), Box<dyn std::error::Error>> {
    let clock = Arc::new(StepClock::default());
    let (state, _connection, _init) = standalone(bare_config(), clock.clone()).await?;
    let cell = OnceLock::new();
    activate_into(&cell, Some(&state))?;
    assert!(activate_into(&cell, Some(&state)).is_err());
    assert!(state.admit().is_ok());
    assert!(state.admit().is_err());
    clock.0.store(60_001, std::sync::atomic::Ordering::SeqCst);
    assert!(state.admit().is_ok());
    Ok(())
}

#[tokio::test]
async fn pairing_extras_cover_invalidate_oversized_bearer_and_closed_delivery()
-> Result<(), Box<dyn std::error::Error>> {
    let (fixture, _) = fixture(true).await?;
    let call = |operation| PairingRequest2 {
        account: "acct".into(),
        operation,
    };
    let invalidated = fixture
        .service
        .pairing_control(call(PairingOperation2::Invalidate))?;
    assert!(invalidated.is_paired && !invalidated.active);
    assert!(
        fixture
            .service
            .pairing_control(call(PairingOperation2::Authenticate {
                bearer: "x".repeat(4097)
            }))
            .is_err()
    );
    // The fixed delivery port is closed, so no challenge can be issued yet.
    let state = fixture.service.crypto.as_ref().ok_or("state")?;
    let pairing = state.pairing.as_ref().ok_or("pairing")?;
    let request = |account| TrustedAccountRequest {
        account,
        peer: &pairing.peer,
        generation: pairing.generation,
    };
    // A paired account issues nothing; an unpaired one reaches the closed port and fails.
    assert!(matches!(
        pairing.owner.begin(&request("acct")).await,
        Ok(tinysecurity::crypto::pairing::BeginOutcome::Inactive)
    ));
    assert!(pairing.owner.begin(&request("fresh")).await.is_err());
    // An oversized password is refused before any derivation.
    assert!(
        fixture
            .service
            .password_crypt(PasswordRequest2 {
                operation: PasswordOperation2::Decrypt {
                    password: "p".repeat(4097),
                    payload: PasswordPayload2 {
                        ciphertext: vec![0; 32],
                        nonce: vec![0; 12],
                        salt: vec![0; 16]
                    }
                }
            })
            .await
            .is_err()
    );
    Ok(())
}
