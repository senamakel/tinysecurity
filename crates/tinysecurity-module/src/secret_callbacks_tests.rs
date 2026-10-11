use super::*;
use tinysecurity_bus::MasterSlotKind2;
#[tokio::test]
async fn fixed_callback_store_has_no_context_free_read_write_delete_or_enumeration_authority()
-> Result<(), Box<dyn std::error::Error>> {
    use tinybus::{broker::Broker, transport::memory::MemoryBus};
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let connection = tinybus::Connection::connect(bus.connect().await?).await?;
    assert!(StoreBroker::new(connection.clone(), "well.known", 1).is_err());
    assert!(StoreBroker::new(connection.clone(), ":1.1", 0).is_err());
    let owner = Arc::new(StoreBroker::new(connection, ":1.1", 1)?);
    let store = CallbackStore::new(
        owner,
        SecretBinding2 {
            backend_id: "a".repeat(32),
            slot: MasterSlotKind2::File,
        },
        ".secret_key".into(),
        false,
    );
    assert!(store.get(".secret_key").await.is_err());
    assert!(store.get("caller-selected").await.is_err());
    assert!(store.set(".secret_key", b"encoded").await.is_err());
    assert!(store.set("caller-selected", b"encoded").await.is_err());
    assert!(store.set(".secret_key", &vec![0; 4097]).await.is_err());
    assert!(store.delete(".secret_key").await.is_err());
    assert!(store.list("").await.is_err());
    assert!(!store.enumerable());
    assert_eq!(store.backend_name(), "confidential_callback");
    assert_eq!(format!("{store:?}"), "CallbackStore([REDACTED])");
    broker.abort();
    Ok(())
}

static WIPED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
pub(super) fn observe_wiped(bytes: &[u8]) {
    assert!(bytes.iter().all(|byte| *byte == 0));
    WIPED.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}
#[test]
fn decoded_reply_and_owned_set_bytes_are_wiped_before_release() {
    let identity = SecretBackendIdentity2 {
        backend_id: "a".repeat(32),
        registration_id: "b".repeat(32),
        generation: 1,
        operation_id: "c".repeat(64),
        phase: SecretPhase2::TargetRead,
        slot: MasterSlotKind2::User,
    };
    let previous = WIPED.load(std::sync::atomic::Ordering::SeqCst);
    drop(LoadReply(SecretBackendLoadResponse2 {
        identity: identity.clone(),
        status: SecretBackendLoadStatus2::Present {
            encoded: b"private-master-fixture".to_vec(),
        },
    }));
    drop(SetRequest(SecretBackendSetRequest2 {
        identity,
        encoded: b"private-master-fixture".to_vec(),
    }));
    assert!(WIPED.load(std::sync::atomic::Ordering::SeqCst) >= previous + 2);
}
