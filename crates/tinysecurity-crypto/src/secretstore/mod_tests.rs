use super::*;
use async_trait::async_trait;
use tinystoragedrivers::Result as DriverResult;
#[derive(Debug)]
struct Denied;
#[async_trait]
impl SecretStore for Denied {
    async fn get(&self, _: &str) -> DriverResult<Option<Zeroizing<Vec<u8>>>> {
        Err(StorageError::unavailable("private fixture payload"))
    }
    async fn set(&self, _: &str, _: &[u8]) -> DriverResult<()> {
        Err(StorageError::unavailable("private fixture payload"))
    }
    async fn delete(&self, _: &str) -> DriverResult<bool> {
        Err(StorageError::unavailable("private fixture payload"))
    }
    async fn list(&self, _: &str) -> DriverResult<Vec<String>> {
        Err(StorageError::unavailable("private fixture payload"))
    }
    fn backend_name(&self) -> &'static str {
        "denied"
    }
}
#[tokio::test]
async fn denied_read_is_not_absence() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let store = SecretStorage::new(Denied, BackendKind::OsKeyring);
    assert_eq!(
        store.get("fixture").await.err().ok_or("expected failure")?,
        Error::KeyringUnavailable
    );
    Ok(())
}
#[tokio::test]
async fn denied_delete_is_not_success() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let store = SecretStorage::new(Denied, BackendKind::OsKeyring);
    assert_eq!(
        store
            .delete("fixture")
            .await
            .err()
            .ok_or("expected failure")?,
        Error::KeyringUnavailable
    );
    Ok(())
}

#[tokio::test]
async fn memory_round_trip_and_backend_identity()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let store = SecretStorage::new(
        tinystoragedrivers::secrets::MemorySecrets::new(),
        BackendKind::Memory,
    );
    assert_eq!(store.kind(), BackendKind::Memory);
    assert!(store.get("fixture").await?.is_none());
    store.set("fixture", b"value").await?;
    assert_eq!(
        &*store.get("fixture").await?.ok_or("expected entry")?,
        b"value"
    );
    assert!(store.delete("fixture").await?);
    assert!(!store.delete("fixture").await?);
    assert_eq!(
        SecretStorage::new(Denied, BackendKind::LocalEncrypted).kind(),
        BackendKind::LocalEncrypted
    );
    assert!(!format!("{store:?}").contains("value"));
    Ok(())
}
#[tokio::test]
async fn denied_write_and_invalid_name_are_content_free()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        SecretStorage::new(Denied, BackendKind::OsKeyring)
            .set("fixture", b"value")
            .await
            .err()
            .ok_or("expected failure")?,
        Error::KeyringUnavailable
    );
    let store = SecretStorage::new(
        tinystoragedrivers::secrets::MemorySecrets::new(),
        BackendKind::Memory,
    );
    assert_eq!(
        store.get("").await.err().ok_or("expected failure")?,
        Error::SecretInvalid
    );
    for kind in [
        ErrorKind::Crypto,
        ErrorKind::Serialization,
        ErrorKind::Backend,
        ErrorKind::Conflict,
    ] {
        let error = project_error(&StorageError::new(kind, "private fixture payload"));
        assert!(!format!("{error:?} {error}").contains("private"));
    }
    Ok(())
}
#[test]
fn historical_ciphertexts_and_raw_json_map_are_unchanged()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let cipher = SecretCipher::new(Zeroizing::new([0x42; 32]), true);
    let lines = include_str!("../../fixtures/enc2_values.txt");
    for (line, expected) in lines.lines().zip(["sk-test-fixture-value", "paßword 🔑"]) {
        assert_eq!(&*cipher.decrypt(line)?, expected);
        assert_eq!(
            &*cipher.decrypt(&format!("enc2:{}", line[5..].to_uppercase()))?,
            expected
        );
    }
    let raw = include_bytes!("../../fixtures/secrets_enc.bin");
    let plain = tinystoragedrivers::secrets::crypto::decrypt(&[0x42; 32], raw)?;
    let map: std::collections::BTreeMap<String, String> = serde_json::from_slice(&plain)?;
    assert_eq!(map["user-1:session_token"], "tok-abc-123");
    assert_eq!(map["user-1:api_key"], "sk-fixture-é中");
    assert_eq!(map["user-2:session_token"], "tok-other");
    assert_eq!(map.len(), 3);
    Ok(())
}
#[test]
fn config_plain_disabled_empty_and_legacy_migration_compatibility()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let enabled = SecretCipher::new(Zeroizing::new([0x42; 32]), true);
    let disabled = SecretCipher::new(Zeroizing::new([0x42; 32]), false);
    assert_eq!(enabled.encrypt("")?, "");
    assert_eq!(disabled.encrypt("plain")?, "plain");
    assert_eq!(&*enabled.decrypt("plain")?, "plain");
    let (plain, migrated) = enabled.decrypt_and_migrate("enc:232021")?;
    assert_eq!(&*plain, "abc");
    let migrated = migrated.ok_or("expected migration")?;
    assert!(migrated.starts_with("enc2:"));
    assert_eq!(&*enabled.decrypt(&migrated)?, "abc");
    assert_eq!(&*disabled.decrypt(&migrated)?, "abc");
    assert_eq!(
        disabled.decrypt_and_migrate("enc:232021")?.1.as_deref(),
        Some("abc")
    );
    assert!(enabled.decrypt_and_migrate("plain")?.1.is_none());
    assert!(enabled.decrypt_and_migrate(&migrated)?.1.is_none());
    assert_eq!(
        enabled.decrypt("enc2:zz").err().ok_or("expected failure")?,
        Error::SecretInvalid
    );
    assert_eq!(
        enabled.decrypt("enc:zz").err().ok_or("expected failure")?,
        Error::SecretInvalid
    );
    assert_eq!(
        enabled.decrypt("enc:bd").err().ok_or("expected failure")?,
        Error::SecretInvalid
    );
    let big = "x".repeat(1_048_577);
    assert_eq!(
        enabled.encrypt(&big).err().ok_or("expected failure")?,
        Error::Limit
    );
    assert_eq!(
        enabled.decrypt(&big).err().ok_or("expected failure")?,
        Error::Limit
    );
    assert_eq!(
        SecretCipher::new(Zeroizing::new([1; 32]), true)
            .decrypt(&migrated)
            .err()
            .ok_or("expected failure")?,
        Error::SecretInvalid
    );
    assert_eq!(format!("{enabled:?}"), "SecretCipher([redacted])");
    Ok(())
}

#[derive(Debug)]
struct DeniedEntry {
    memory: tinystoragedrivers::secrets::MemorySecrets,
    deletes: std::sync::atomic::AtomicUsize,
    writes: std::sync::atomic::AtomicUsize,
}
#[async_trait]
impl SecretStore for DeniedEntry {
    async fn get(&self, _: &str) -> DriverResult<Option<Zeroizing<Vec<u8>>>> {
        Err(StorageError::unavailable("private entry"))
    }
    async fn set(&self, _: &str, _: &[u8]) -> DriverResult<()> {
        self.writes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(StorageError::unavailable("private entry"))
    }
    async fn delete(&self, _: &str) -> DriverResult<bool> {
        self.deletes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(StorageError::unavailable("private entry"))
    }
    async fn list(&self, _: &str) -> DriverResult<Vec<String>> {
        Err(StorageError::unavailable("private entry"))
    }
    fn backend_name(&self) -> &'static str {
        "fixture"
    }
}
#[tokio::test]
async fn denied_read_and_delete_leave_existing_entry_unchanged()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let memory = tinystoragedrivers::secrets::MemorySecrets::new();
    memory.set("fixture", b"unchanged").await?;
    let store = SecretStorage::new(
        DeniedEntry {
            memory,
            deletes: std::sync::atomic::AtomicUsize::new(0),
            writes: std::sync::atomic::AtomicUsize::new(0),
        },
        BackendKind::OsKeyring,
    );
    assert_eq!(
        store
            .get("fixture")
            .await
            .err()
            .ok_or("expected read denial")?,
        Error::KeyringUnavailable
    );
    assert_eq!(
        store
            .delete("fixture")
            .await
            .err()
            .ok_or("expected deletion denial")?,
        Error::KeyringUnavailable
    );
    assert_eq!(
        &*store
            .store
            .memory
            .get("fixture")
            .await?
            .ok_or("missing fixture")?,
        b"unchanged"
    );
    assert_eq!(
        store.store.writes.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert_eq!(
        store
            .store
            .deletes
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    Ok(())
}
