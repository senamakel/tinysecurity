//! Synthetic sender-bound callback fixture shared by unit and native acceptance.
#[path = "../approval_native_contract/callback.rs"]
pub(crate) mod callback;
#[path = "../approval_native_contract/store.rs"]
pub(crate) mod store;
use std::sync::{Arc, Mutex, atomic::AtomicBool};
use tinysecurity_bus::*;
pub(crate) fn audit(sequence: u64) -> AuditCorrelation2 {
    AuditCorrelation2 {
        event_id: format!("{sequence:032x}"),
        expected_tail: sequence - 1,
        generation: 1,
    }
}
pub(crate) fn registration() -> ApprovalScope2 {
    ApprovalScope2 {
        scope_id: "a".repeat(32),
        subject: SubjectScope {
            user: "fixture-user".into(),
            workspace: "fixture-workspace".into(),
            agent: "fixture-agent".into(),
        },
        policy_ref: "immutable-device-fixture".into(),
        generation: 1,
        ceiling: AccessTier::Full,
        require_approval: true,
        auto_approve_all: false,
    }
}
pub(crate) fn device_config() -> DeviceConfig2 {
    DeviceConfig2 {
        scopes: vec![DeviceScope2 {
            scope_id: "a".repeat(32),
            origin: Origin::Operator,
            static_secret: Some([7; 32]),
        }],
        max_handles: 32,
        max_in_flight: 4,
        operations_per_minute: 4096,
        max_ttl_ms: 300000,
        max_message_bytes: 1024,
        max_bootstrap_nonces: 64,
    }
}
pub(crate) fn audit_config(native_path: Option<String>) -> AuditConfig2 {
    AuditConfig2 {
        scope: registration().subject,
        stream_id: "c".repeat(32),
        timeout_ms: 30000,
        required: true,
        native_path,
        max_bytes: 1_000_000,
        max_archives: 3,
        journal_max_bytes: 4_000_000,
        journal_max_events: 10000,
    }
}
pub(crate) fn request(instance: u64, operation: DeviceOperation2) -> DeviceRequest2 {
    DeviceRequest2 {
        scope_id: "a".repeat(32),
        call_id: format!("fixture-{instance}"),
        ttl_ms: 300000,
        operation,
    }
}
pub(crate) async fn serve_callbacks(
    host: &tinybus::Connection,
    module: &tinybus::BusName,
    store: &Arc<Mutex<store::DiskStore>>,
    reentrant: bool,
) -> tinybus::Result<()> {
    let reentrant = Arc::new(AtomicBool::new(reentrant));
    let scope = tinysecurity::approval::scope_handle(&registration().subject)
        .map_err(|_| tinybus::Error::failed("fixture scope"))?;
    for interface in [
        callback_names2::APPROVAL_STORE,
        callback_names2::APPROVAL_PROMPT,
    ] {
        host.serve_at(
            callback_names2::OBJECT_PATH.parse()?,
            callback::Callback {
                module: module.clone(),
                host: host.clone(),
                interface: interface.parse()?,
                scope: scope.clone(),
                store: store.clone(),
                reentrant: reentrant.clone(),
                prompt_failure: Arc::new(AtomicBool::new(false)),
            },
        )
        .await?;
    }
    Ok(())
}
pub(crate) async fn decide(
    proxy: &tinybus::Proxy,
    store: &Arc<Mutex<store::DiskStore>>,
    row: ApprovalRow2,
    sequence: u64,
    choice: ApprovalChoice2,
) -> tinybus::Result<ApprovalRow2> {
    let ticket = store
        .lock()
        .map_err(|_| tinybus::Error::failed("fixture store"))?
        .human_action(row.clone(), choice)?;
    proxy
        .call(
            names::methods::DECIDE2,
            (DecideRequest2 {
                scope_id: "a".repeat(32),
                request_id: row.request_id,
                decision_ticket: ticket,
                audit: audit(sequence),
            },),
        )
        .await
}
pub(crate) async fn run(
    proxy: &tinybus::Proxy,
    store: &Arc<Mutex<store::DiskStore>>,
    sequence: &mut u64,
    operation: DeviceOperation2,
) -> tinybus::Result<DeviceResponse2> {
    let request = request(*sequence, operation);
    let row: ApprovalRow2 = proxy
        .call_confidential(
            names::methods::EVALUATE_DEVICE2,
            (EvaluateDeviceRequest2 {
                request: request.clone(),
                audit: audit(*sequence),
            },),
        )
        .await?;
    let row = if row.state == ApprovalLifecycle2::Pending {
        decide(proxy, store, row, *sequence + 1, ApprovalChoice2::Once).await?
    } else {
        row
    };
    if row.state != ApprovalLifecycle2::Approved {
        return Err(tinybus::Error::failed("fixture approval"));
    }
    let result = proxy
        .call_confidential(
            names::methods::EXECUTE_DEVICE2,
            (ExecuteDeviceRequest2 {
                request,
                request_id: row.request_id,
                audit: audit(*sequence + 2),
            },),
        )
        .await;
    *sequence += 3;
    result
}
