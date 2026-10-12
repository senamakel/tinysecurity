//! Fixed authenticated confidential callbacks own bounded zeroizing output slots.
#[path = "../approval_native_contract/callback.rs"]
mod callback;
#[path = "../approval_native_contract/store.rs"]
mod store;
use async_trait::async_trait;
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Mutex, OnceLock, atomic::AtomicBool},
    time::Duration,
};
use tinybus::{
    BusName, CallContext, Connection, Interface, InterfaceName, MemberName, broker::Broker,
    module::ModuleHost, transport::memory::MemoryBus,
};
use tinysecurity_bus::{
    AccessTier, ApprovalChoice2, ApprovalConfig2, ApprovalLifecycle2, ApprovalRow2, ApprovalScope2,
    AuditConfig2, AuditCorrelation2, AuditSinkRequest2, DecideRequest2,
    EvaluateSecretCipherRequest2, EvaluateSecretRequest2, ExecuteSecretCipherRequest2,
    ExecuteSecretRequest2, MasterPurpose2, MasterSlotKind2, ModuleConfig, Origin, PolicyInfo,
    RedactorConfig, SecretBackendLoadRequest2, SecretBackendLoadResponse2,
    SecretBackendLoadStatus2, SecretBackendSetRequest2, SecretBackendSetResponse2,
    SecretBackendSetStatus2, SecretBinding2, SecretCipherConfig2, SecretCipherDeliveryIdentity2,
    SecretCipherDeliveryRequest2, SecretCipherDeliveryResponse2, SecretCipherKind2,
    SecretCipherPending2, SecretCipherRequest2, SecretCipherResponse2, SecretConfig2,
    SecretLimits2, SecretOperation2, SecretPhase2, SecretRegistration2, SecretRequest2,
    SecretResponse2, SubjectScope, callback_names2, names,
};
use zeroize::Zeroizing;
fn denied() -> tinybus::Error {
    tinybus::Error::failed("native fixture denied")
}
fn audit(sequence: u64) -> AuditCorrelation2 {
    AuditCorrelation2 {
        event_id: format!("{sequence:032x}"),
        expected_tail: sequence - 1,
        generation: 1,
    }
}
fn registration() -> ApprovalScope2 {
    ApprovalScope2 {
        scope_id: "a".repeat(32),
        subject: SubjectScope {
            user: "fixture-user".into(),
            workspace: "fixture-workspace".into(),
            agent: "fixture-agent".into(),
        },
        policy_ref: "native-cipher-policy".into(),
        generation: 1,
        ceiling: AccessTier::Full,
        require_approval: false,
        auto_approve_all: true,
    }
}
struct Slot {
    identity: SecretCipherDeliveryIdentity2,
    plain: Zeroizing<Vec<u8>>,
    replacement: Option<Zeroizing<Vec<u8>>>,
}
struct State {
    mode: u32,
    module: Mutex<Option<BusName>>,
    store: Arc<Mutex<store::DiskStore>>,
    sink: tinysecurity::audit::JsonlSink,
    target: Mutex<Option<Zeroizing<Vec<u8>>>>,
    slots: Mutex<BTreeMap<u16, Slot>>,
    prompts: Mutex<u32>,
}
static CALLBACK_STATE: OnceLock<Arc<State>> = OnceLock::new();
static CALLBACK_READY: OnceLock<tokio::sync::Notify> = OnceLock::new();
static CALLBACK_CONNECTION: OnceLock<Connection> = OnceLock::new();
mod admitted_callbacks {
    async fn setup(connection: tinybus::Connection, _: serde_json::Value) -> tinybus::Result<()> {
        use super::{
            CALLBACK_CONNECTION, CALLBACK_READY, CALLBACK_STATE, Callback, callback_names2, denied,
        };
        let state = CALLBACK_STATE.get().ok_or_else(denied)?.clone();
        for interface in [
            callback_names2::APPROVAL_STORE,
            callback_names2::APPROVAL_PROMPT,
            callback_names2::AUDIT_SINK,
            callback_names2::SECRET_BACKEND,
            callback_names2::SECRET_CIPHER_CONSUMER,
        ] {
            connection
                .serve_at(
                    callback_names2::OBJECT_PATH.parse()?,
                    Callback {
                        state: state.clone(),
                        host: connection.clone(),
                        interface: interface.parse()?,
                    },
                )
                .await?;
        }
        CALLBACK_CONNECTION.set(connection).map_err(|_| denied())?;
        CALLBACK_READY
            .get_or_init(tokio::sync::Notify::new)
            .notify_one();
        Ok(())
    }
    tinybus_module::module_export_static! { setup = setup, config = serde_json::Value,
    worker_threads = 1, provides = ["ai.tinyhumans.tinysecurity.NativeCipherFixture"],
    methods = [], signals = [], requires = [], optional = [], lazy = false, }
}
struct Callback {
    state: Arc<State>,
    host: Connection,
    interface: InterfaceName,
}
#[async_trait]
impl Interface for Callback {
    fn name(&self) -> InterfaceName {
        self.interface.clone()
    }
    fn members(&self) -> Vec<MemberName> {
        let members: &[&str] = match self.interface.as_str() {
            callback_names2::APPROVAL_STORE => &[callback_names2::LOAD, callback_names2::CAS],
            callback_names2::APPROVAL_PROMPT => {
                &[callback_names2::PROMPT, callback_names2::VERIFY_HUMAN]
            }
            callback_names2::SECRET_BACKEND => &[callback_names2::LOAD, callback_names2::SET],
            callback_names2::AUDIT_SINK => &[callback_names2::APPEND],
            _ => &[callback_names2::DELIVER],
        };
        members.iter().filter_map(|s| s.parse().ok()).collect()
    }
    fn requires_confidential(&self, _: &MemberName) -> bool {
        matches!(
            self.interface.as_str(),
            callback_names2::SECRET_BACKEND
                | callback_names2::SECRET_CIPHER_CONSUMER
                | callback_names2::AUDIT_SINK
        )
    }
    async fn call(
        &self,
        _: &MemberName,
        _: serde_json::Value,
    ) -> tinybus::Result<serde_json::Value> {
        Err(denied())
    }
    async fn call_with_context(
        &self,
        member: &MemberName,
        args: serde_json::Value,
        context: &CallContext,
    ) -> tinybus::Result<serde_json::Value> {
        let module = self
            .state
            .module
            .lock()
            .map_err(|_| denied())?
            .clone()
            .ok_or_else(denied)?;
        if context.authenticated_sender() != Some(&module) {
            return Err(denied());
        }
        if matches!(
            self.interface.as_str(),
            callback_names2::APPROVAL_STORE | callback_names2::APPROVAL_PROMPT
        ) {
            if member.as_str() == callback_names2::PROMPT {
                *self.state.prompts.lock().map_err(|_| denied())? += 1;
            }
            let callback = callback::Callback {
                module,
                host: self.host.clone(),
                interface: self.interface.clone(),
                scope: tinysecurity::approval::scope_handle(&registration().subject)
                    .map_err(|_| denied())?,
                store: self.state.store.clone(),
                reentrant: Arc::new(AtomicBool::new(false)),
                prompt_failure: Arc::new(AtomicBool::new(false)),
            };
            return callback.call_with_context(member, args, context).await;
        }
        match member.as_str() {
            callback_names2::APPEND => self.append(args),
            callback_names2::LOAD => self.load_secret(args),
            callback_names2::SET => self.set_secret(args),
            callback_names2::DELIVER => self.stage(args).await,
            _ => Err(denied()),
        }
    }
}
impl Callback {
    fn append(&self, args: serde_json::Value) -> tinybus::Result<serde_json::Value> {
        let (request,): (AuditSinkRequest2,) = serde_json::from_value(args)?;
        let phase: serde_json::Value = serde_json::from_str(&request.events[0].arguments_json)?;
        if (self.state.mode == 10 && phase["phase"] == "output-stage")
            || (self.state.mode == 11 && phase["phase"] == "publication")
        {
            return Err(denied());
        }
        serde_json::to_value(self.state.sink.append(&request).map_err(|_| denied())?)
            .map_err(Into::into)
    }
    fn load_secret(&self, args: serde_json::Value) -> tinybus::Result<serde_json::Value> {
        let (request,): (SecretBackendLoadRequest2,) = serde_json::from_value(args)?;
        if request.identity.registration_id != "b".repeat(32) || request.identity.generation != 1 {
            return Err(denied());
        }
        let mut identity = request.identity;
        let target = self.state.target.lock().map_err(|_| denied())?;
        let encoded = if identity.phase == SecretPhase2::LegacyRead {
            if self.state.mode == 2 && identity.backend_id == "d".repeat(32) {
                Some(Zeroizing::new("AA".repeat(32).into_bytes()))
            } else {
                None
            }
        } else {
            target.clone()
        };
        let mut status = encoded.map_or(SecretBackendLoadStatus2::Absent, |v| {
            SecretBackendLoadStatus2::Present {
                encoded: v.to_vec(),
            }
        });
        if self.state.mode == 3 {
            identity.operation_id.push('x');
        }
        if self.state.mode == 4 {
            status = SecretBackendLoadStatus2::Present {
                encoded: vec![0; 4097],
            };
        }
        if self.state.mode == 5 {
            status = SecretBackendLoadStatus2::Present {
                encoded: b"invalid".to_vec(),
            };
        }
        if self.state.mode == 6 && identity.phase == SecretPhase2::TargetReadback {
            status = SecretBackendLoadStatus2::Present {
                encoded: "AB".repeat(32).into_bytes(),
            };
        }
        serde_json::to_value(SecretBackendLoadResponse2 { identity, status }).map_err(Into::into)
    }
    fn set_secret(&self, args: serde_json::Value) -> tinybus::Result<serde_json::Value> {
        let (mut request,): (SecretBackendSetRequest2,) = serde_json::from_value(args)?;
        let encoded = Zeroizing::new(std::mem::take(&mut request.encoded));
        if request.identity.phase != SecretPhase2::TargetSet
            || request.identity.backend_id != "c".repeat(32)
        {
            return Err(denied());
        }
        *self.state.target.lock().map_err(|_| denied())? = Some(encoded);
        serde_json::to_value(SecretBackendSetResponse2 {
            identity: request.identity,
            status: SecretBackendSetStatus2::Stored,
        })
        .map_err(Into::into)
    }
    async fn stage(&self, args: serde_json::Value) -> tinybus::Result<serde_json::Value> {
        let (mut request,): (SecretCipherDeliveryRequest2,) = serde_json::from_value(args)?;
        let plain = Zeroizing::new(std::mem::take(&mut request.plaintext));
        let replacement = request.replacement.take().map(Zeroizing::new);
        let mut identity = request.identity;
        let now = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| denied())?
                .as_millis(),
        )
        .map_err(|_| denied())?;
        if now >= identity.expires_at_ms
            || identity.consumer_id != "f".repeat(32)
            || identity.registration_id != "b".repeat(32)
            || identity.generation != 1
            || identity.slot >= 2
            || plain.len() > 2_097_213
            || replacement.as_ref().is_some_and(|p| p.len() > 2_097_213)
        {
            return Err(denied());
        }
        {
            let mut slots = self.state.slots.lock().map_err(|_| denied())?;
            if slots.contains_key(&identity.slot) {
                return Err(denied());
            }
            slots.insert(
                identity.slot,
                Slot {
                    identity: identity.clone(),
                    plain,
                    replacement,
                },
            );
        }
        if self.state.mode == 7 {
            identity.operation_id.push('x');
        }
        if self.state.mode == 8 {
            identity.output_id.push('x');
        }
        if self.state.mode == 12 {
            std::future::pending::<()>().await;
        }
        serde_json::to_value(SecretCipherDeliveryResponse2 {
            identity,
            staged: self.state.mode != 9,
        })
        .map_err(Into::into)
    }
}
fn make_state(
    root: &Path,
    mode: u32,
) -> std::result::Result<Arc<State>, Box<dyn std::error::Error>> {
    Ok(Arc::new(State {
        mode,
        module: Mutex::new(None),
        store: Arc::new(Mutex::new(store::DiskStore::open(
            &root.join("approvals.journal"),
        )?)),
        sink: tinysecurity::audit::JsonlSink::with_journal_capacity(
            &root.join("audit"),
            1_000_000,
            3,
            4_000_000,
            10000,
            tinysecurity::Redactor::new(&RedactorConfig::default())?,
        )?,
        target: Mutex::new(
            (!matches!(mode, 1 | 2 | 6)).then(|| Zeroizing::new("AA".repeat(32).into_bytes())),
        ),
        slots: Mutex::new(BTreeMap::new()),
        prompts: Mutex::new(0),
    }))
}
fn configuration(
    host: &Connection,
    mode: u32,
) -> std::result::Result<ModuleConfig, Box<dyn std::error::Error>> {
    let mut config = ModuleConfig {
        trusted_host: host.unique_name().map(|n| n.to_string()),
        approvals: Some(ApprovalConfig2 {
            scopes: vec![registration()],
            timeout_ms: 10000,
        }),
        audit: Some(AuditConfig2 {
            scope: registration().subject,
            stream_id: "e".repeat(32),
            timeout_ms: 10000,
            required: true,
            native_path: None,
            max_bytes: 1_000_000,
            max_archives: 3,
            journal_max_bytes: 4_000_000,
            journal_max_events: 10000,
        }),
        secret: Some(SecretConfig2 {
            registrations: vec![SecretRegistration2 {
                registration_id: "b".repeat(32),
                approval_scope_id: "a".repeat(32),
                origin: Origin::Operator,
                purpose: MasterPurpose2::ConfigUserMaster,
                target: SecretBinding2 {
                    backend_id: "c".repeat(32),
                    slot: MasterSlotKind2::User,
                },
                legacy: vec![SecretBinding2 {
                    backend_id: "d".repeat(32),
                    slot: MasterSlotKind2::File,
                }],
            }],
            limits: SecretLimits2 {
                operations_per_minute: 4096,
                ..Default::default()
            },
            callback_timeout_ms: 1000,
        }),
        secret_cipher: Some(SecretCipherConfig2 {
            registration_id: "b".repeat(32),
            consumer_id: "f".repeat(32),
            enabled: mode != 13,
            slots: 2,
            timeout_ms: 1000,
        }),
        ..Default::default()
    };
    if mode == 17 {
        let secret = config.secret.as_mut().ok_or("native app config")?;
        secret.registrations[0].purpose = MasterPurpose2::AppEncryptionMaster;
        secret.registrations[0].target.slot = MasterSlotKind2::App;
        secret.registrations[0].legacy.clear();
        config.secret_cipher = None;
    }
    if mode == 14 {
        config.contract_version = (1, 10);
        config.secret_cipher = None;
    }
    if mode == 15 {
        config
            .secret_cipher
            .as_mut()
            .ok_or("native cipher config")?
            .consumer_id
            .clear();
    }
    if mode == 16 {
        config
            .secret_cipher
            .as_mut()
            .ok_or("native cipher config")?
            .registration_id = "a".repeat(32);
    }
    Ok(config)
}
async fn acquire_master(proxy: &tinybus::Proxy, state: &State) -> tinybus::Result<SecretResponse2> {
    let request = SecretRequest2 {
        registration_id: "b".repeat(32),
        call_id: "native-master".into(),
        ttl_ms: 30000,
        operation: if state.mode == 17 {
            SecretOperation2::ResolveAppMaster
        } else {
            SecretOperation2::ResolveConfigMaster
        },
    };
    let row: ApprovalRow2 = proxy
        .call_confidential(
            names::methods::EVALUATE_SECRET2,
            (EvaluateSecretRequest2 {
                request: request.clone(),
                audit: audit(1),
            },),
        )
        .await?;
    assert_eq!(row.state, ApprovalLifecycle2::Pending); // permissive policy cannot replace Human Once
    let ticket = state
        .store
        .lock()
        .map_err(|_| denied())?
        .human_action(row.clone(), ApprovalChoice2::Once)?;
    let _: ApprovalRow2 = proxy
        .call(
            names::methods::DECIDE2,
            (DecideRequest2 {
                scope_id: "a".repeat(32),
                request_id: row.request_id.clone(),
                decision_ticket: ticket,
                audit: audit(2),
            },),
        )
        .await?;
    proxy
        .call_confidential::<SecretResponse2>(
            names::methods::EXECUTE_SECRET2,
            (ExecuteSecretRequest2 {
                request,
                request_id: row.request_id,
                audit: audit(3),
            },),
        )
        .await
}
async fn exercise_cipher(
    proxy: &tinybus::Proxy,
    state: &State,
    handle: &str,
) -> std::result::Result<u64, Box<dyn std::error::Error>> {
    let mode = state.mode;
    let mut sequence = 4;
    let mut encrypted = None;
    for (call, operation, input) in [
        (1, SecretCipherKind2::Encrypt, b"private-output".to_vec()),
        (2, SecretCipherKind2::Decrypt, b"private-output".to_vec()),
        (3, SecretCipherKind2::Encrypt, Vec::new()),
    ] {
        if (7..=12).contains(&mode) && call != 2 {
            continue;
        }
        let request = cipher_request(handle, call, operation, input);
        let response = execute(proxy, request, &mut sequence).await;
        if (7..=12).contains(&mode) && (call == 2 || mode == 13) {
            assert!(response.is_err());
            state.slots.lock().map_err(|_| denied())?.clear();
            break;
        }
        let response = response?;
        assert!(!serde_json::to_string(&response)?.contains("private-output"));
        match response {
            SecretCipherResponse2::Ciphertext { ciphertext } => {
                assert!(ciphertext.starts_with("enc2:"));
                encrypted = Some(ciphertext);
            }
            SecretCipherResponse2::Delivered {
                identity,
                replacement_ciphertext,
                ..
            } => {
                let slot = state
                    .slots
                    .lock()
                    .map_err(|_| denied())?
                    .remove(&identity.slot)
                    .ok_or("native slot missing")?;
                assert_eq!(slot.identity, identity);
                assert!(replacement_ciphertext.is_none() && slot.replacement.is_none());
                assert!(slot.plain.as_slice().eq(if call == 3 {
                    &b""[..]
                } else {
                    &b"private-output"[..]
                }));
            }
        }
    }
    if let Some(encrypted) = encrypted
        && !(7..=12).contains(&mode)
    {
        let response = execute(
            proxy,
            cipher_request(
                handle,
                4,
                SecretCipherKind2::Decrypt,
                encrypted.into_bytes(),
            ),
            &mut sequence,
        )
        .await?;
        let SecretCipherResponse2::Delivered { identity, .. } = response else {
            return Err("native decrypt classification".into());
        };
        let slot = state
            .slots
            .lock()
            .map_err(|_| denied())?
            .remove(&identity.slot)
            .ok_or("native decrypt slot")?;
        assert_eq!(slot.identity, identity);
        assert!(slot.plain.as_slice().eq(b"private-output"));
    }
    exercise_migration(proxy, state, handle, &mut sequence).await?;
    Ok(sequence)
}
async fn exercise_migration(
    proxy: &tinybus::Proxy,
    state: &State,
    handle: &str,
    sequence: &mut u64,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    if matches!(state.mode, 0 | 13) {
        for (call, stored) in [
            (5, b"enc:dad8c3dccbdecf87c5dfdedadfde".as_slice()),
            (6, b"enc:DAD8C3DCCBDECF87C5DFDEDADFDE".as_slice()),
        ] {
            let response = execute(
                proxy,
                cipher_request(
                    handle,
                    call,
                    SecretCipherKind2::DecryptAndMigrate,
                    stored.to_vec(),
                ),
                sequence,
            )
            .await?;
            let SecretCipherResponse2::Delivered {
                identity,
                migrated,
                replacement_ciphertext,
            } = response
            else {
                return Err("native migration classification".into());
            };
            let slot = state
                .slots
                .lock()
                .map_err(|_| denied())?
                .remove(&identity.slot)
                .ok_or("native migration slot")?;
            assert!(slot.identity == identity && migrated);
            assert!(slot.plain.as_slice().eq(b"private-output"));
            let replacement = slot.replacement.ok_or("native migration replacement")?;
            if state.mode == 0 {
                let ciphertext =
                    replacement_ciphertext.ok_or("native public migration ciphertext")?;
                assert!(
                    ciphertext.starts_with("enc2:")
                        && replacement.as_slice().eq(ciphertext.as_bytes())
                );
            } else {
                assert!(
                    replacement_ciphertext.is_none()
                        && replacement.as_slice().eq(b"private-output")
                );
            }
        }
    }
    Ok(())
}
async fn reject_wrong_peer(bus: &MemoryBus, module: &BusName, handle: &str) -> tinybus::Result<()> {
    let attacker = Connection::connect(bus.connect().await?).await?;
    assert!(
        attacker
            .proxy(module.as_str(), names::OBJECT_PATH, names::INTERFACE)?
            .with_timeout(Duration::from_millis(100))
            .call_confidential::<SecretCipherPending2>(
                names::methods::EVALUATE_SECRET_CIPHER2,
                (EvaluateSecretCipherRequest2 {
                    request: cipher_request(
                        handle,
                        99,
                        SecretCipherKind2::Decrypt,
                        b"private-output".to_vec()
                    ),
                    audit: audit(99)
                },)
            )
            .await
            .is_err()
    );
    Ok(())
}
async fn start_callbacks(
    lifecycle: &ModuleHost,
    state: &Arc<State>,
) -> tinybus::Result<Connection> {
    CALLBACK_STATE.set(state.clone()).map_err(|_| denied())?;
    let mut callbacks = admitted_callbacks::linked_module()?;
    // Both exports originate in this package; give the host-trusted linked
    // fixture its own descriptor/manifest identity before ordinary admission.
    callbacks.manifest.module.name = "tinysec-native-cipher-fixture".into();
    callbacks.descriptor = tinybus::module::abi::TbAbiDescriptor::current(
        "tinysec-native-cipher-fixture",
        env!("CARGO_PKG_VERSION"),
    );
    lifecycle.attach_linked_with_config(callbacks, serde_json::json!({}))?;
    CALLBACK_READY
        .get_or_init(tokio::sync::Notify::new)
        .notified()
        .await;
    let host = CALLBACK_CONNECTION.get().ok_or_else(denied)?.clone();
    Ok(host)
}
async fn generation_boundary(
    lifecycle: &ModuleHost,
    name: &str,
    configuration: &ModuleConfig,
    proxy: &tinybus::Proxy,
    handle: &str,
    sequence: u64,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Use the actual tail left by all successful routine calls.
    let pending: SecretCipherPending2 = proxy
        .call_confidential(
            names::methods::EVALUATE_SECRET_CIPHER2,
            (EvaluateSecretCipherRequest2 {
                request: cipher_request(
                    handle,
                    80,
                    SecretCipherKind2::Decrypt,
                    b"private-output".to_vec(),
                ),
                audit: audit(sequence),
            },),
        )
        .await?;
    lifecycle
        .reinitialize(name, serde_json::to_value(configuration)?)
        .await?;
    let info: PolicyInfo = proxy.call(names::methods::POLICY_INFO, ()).await?;
    assert_eq!(info.generation, 2);
    assert!(
        proxy
            .call_confidential::<SecretCipherResponse2>(
                names::methods::EXECUTE_SECRET_CIPHER2,
                (ExecuteSecretCipherRequest2 {
                    request: cipher_request(
                        handle,
                        80,
                        SecretCipherKind2::Decrypt,
                        b"private-output".to_vec()
                    ),
                    pending_id: pending.pending_id,
                    audit: audit(sequence + 1),
                    delivery_audit: audit(sequence + 2),
                    completion_audit: audit(sequence + 3)
                },)
            )
            .await
            .is_err()
    );
    let mut omitted = configuration.clone();
    omitted.secret = None;
    omitted.secret_cipher = None;
    lifecycle
        .reinitialize(name, serde_json::to_value(omitted)?)
        .await?;
    let info: PolicyInfo = proxy.call(names::methods::POLICY_INFO, ()).await?;
    assert_eq!(info.generation, 3);
    Ok(())
}
async fn reject_invalid_config(
    lifecycle: &ModuleHost,
    host: &Connection,
    loaded: tinybus::Result<tinybus::module::ModuleInfo>,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    if let Ok(info) = loaded {
        assert!(
            host.proxy(
                info.manifest.bus_name.as_str(),
                names::OBJECT_PATH,
                names::INTERFACE
            )?
            .with_timeout(Duration::from_secs(5))
            .call::<PolicyInfo>(names::methods::POLICY_INFO, ())
            .await
            .is_err()
        );
        // Asynchronous adapter setup errors do not report SDK Failed here.
        // The relevant boundary is that invalid authority never serves.
        assert!(lifecycle.list().iter().all(|current| {
            current.name != info.name
                || !matches!(
                    current.state,
                    tinybus::module::ModuleState::Ready | tinybus::module::ModuleState::Serving
                )
        }));
    }
    Ok(())
}
pub(super) async fn run(
    library: &Path,
    mode: u32,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let hash = tinybus::module::sha256_file(library)?;
    let name = library
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("native fixture filename")?;
    std::fs::write(
        library
            .parent()
            .ok_or("native fixture parent")?
            .join("modules.toml"),
        format!("\"{name}\" = \"{hash}\"\n"),
    )?;
    let (_directory, root) = super::namespace::create()?;
    let bus = MemoryBus::new();
    let broker = Broker::new();
    let task = broker.spawn(bus.clone());
    let lifecycle = ModuleHost::new(broker);
    let state = make_state(&root, mode)?;
    // A confidential destination must itself be SDK-admitted. Register a fixed
    // trusted native callback module before loading the real TinySecurity cdylib.
    // Ordinary unattested host connections remain denied by the broker.
    let host = start_callbacks(&lifecycle, &state).await?;
    let config = configuration(&host, mode)?;
    let loaded = lifecycle.load_file_with_config(library, serde_json::to_value(&config)?);
    if matches!(mode, 15 | 16) {
        reject_invalid_config(&lifecycle, &host, loaded).await?;
        task.abort();
        return Ok(());
    }
    let loaded = loaded?;
    let module = host
        .name_owner(loaded.manifest.bus_name.as_str())
        .await?
        .ok_or("native module peer")?;
    *state.module.lock().map_err(|_| denied())? = Some(module.clone());
    let proxy = host
        .proxy(module.as_str(), names::OBJECT_PATH, names::INTERFACE)?
        .with_timeout(Duration::from_secs(5));
    assert!(proxy.attestation().await?.is_some());
    let resolved = acquire_master(&proxy, &state).await;
    if (3..=6).contains(&mode) {
        assert!(resolved.is_err());
        task.abort();
        return Ok(());
    }
    let SecretResponse2::MasterHandle { handle, .. } = resolved?;
    assert_eq!(*state.prompts.lock().map_err(|_| denied())?, 1);
    if matches!(mode, 14 | 17) {
        assert!(
            proxy
                .call_confidential::<SecretCipherPending2>(
                    names::methods::EVALUATE_SECRET_CIPHER2,
                    (EvaluateSecretCipherRequest2 {
                        request: cipher_request(
                            &handle,
                            1,
                            SecretCipherKind2::Decrypt,
                            b"private-output".to_vec()
                        ),
                        audit: audit(4)
                    },)
                )
                .await
                .is_err()
        );
        task.abort();
        return Ok(());
    }
    let sequence = exercise_cipher(&proxy, &state, &handle).await?;
    assert_eq!(*state.prompts.lock().map_err(|_| denied())?, 1); // routine operations never prompt
    reject_wrong_peer(&bus, &module, &handle).await?;
    if mode == 0 {
        generation_boundary(&lifecycle, &loaded.name, &config, &proxy, &handle, sequence).await?;
    }
    let mut changed = config.clone();
    changed
        .secret_cipher
        .as_mut()
        .ok_or("native initialized cipher")?
        .consumer_id = "d".repeat(32);
    assert!(
        lifecycle
            .reinitialize(&loaded.name, serde_json::to_value(changed)?)
            .await
            .is_err()
    );
    state.slots.lock().map_err(|_| denied())?.clear();
    lifecycle.shutdown(Duration::from_secs(5)).await;
    task.abort();
    assert_eq!(hash, tinybus::module::sha256_file(library)?);
    Ok(())
}
fn cipher_request(
    handle: &str,
    call: u64,
    operation: SecretCipherKind2,
    input: Vec<u8>,
) -> SecretCipherRequest2 {
    SecretCipherRequest2 {
        registration_id: "b".repeat(32),
        master_handle: handle.into(),
        call_id: format!("native-{call}"),
        operation,
        input,
        ttl_ms: 30000,
    }
}
async fn execute(
    proxy: &tinybus::Proxy,
    request: SecretCipherRequest2,
    sequence: &mut u64,
) -> tinybus::Result<SecretCipherResponse2> {
    let pending: SecretCipherPending2 = proxy
        .call_confidential(
            names::methods::EVALUATE_SECRET_CIPHER2,
            (EvaluateSecretCipherRequest2 {
                request: request.clone(),
                audit: audit(*sequence),
            },),
        )
        .await?;
    *sequence += 1;
    let execute = ExecuteSecretCipherRequest2 {
        request,
        pending_id: pending.pending_id,
        audit: audit(*sequence),
        delivery_audit: audit(*sequence + 1),
        completion_audit: audit(*sequence + 2),
    };
    *sequence += 3;
    let response = proxy
        .call_confidential(names::methods::EXECUTE_SECRET_CIPHER2, (&execute,))
        .await;
    assert!(
        proxy
            .call_confidential::<SecretCipherResponse2>(
                names::methods::EXECUTE_SECRET_CIPHER2,
                (&execute,)
            )
            .await
            .is_err()
    );
    response
}
