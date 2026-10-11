//! Loaded permissions tied to the actual OS sink, including precommit rotation denial.
use super::{audit_config, module_peer};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    fs::OpenOptions,
    path::{Path, PathBuf},
    time::Duration,
};
use tinybus::{Connection, broker::Broker, module::ModuleHost, transport::memory::MemoryBus};
use tinysecurity_bus::{
    AccessTier, AuditCorrelation2, AuditedRequest2, CallerContext, Check, CheckAuditedResponse2,
    CheckRequest, ModuleConfig, Verdict, names,
};

fn namespace() -> std::result::Result<(tempfile::TempDir, PathBuf), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    let directory = tempfile::tempdir()?;
    #[cfg(windows)]
    let directory = tempfile::tempdir_in(
        std::env::var_os("TINYSECURITY_AUDIT_TEST_ROOT")
            .ok_or("audit namespace not provisioned")?,
    )?;
    #[cfg(windows)]
    provision(directory.path())?;
    #[cfg(unix)]
    let path = directory.path().canonicalize()?.join("audit");
    #[cfg(windows)]
    let path = directory.path().join("audit");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    options
        .open(path.with_file_name("audit.journal"))?
        .sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path.with_file_name("audit.journal"))?
            .permissions()
            .mode()
            & 0o777;
        eprintln!("audit-stage=native-journal-installer mode={mode}");
        assert_eq!(
            mode, 0o600,
            "the fixture must restrict the authority before module initialization"
        );
    }
    Ok((directory, path))
}

#[cfg(windows)]
fn provision(path: &Path) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let script = r"
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetOwner($identity.User)
$acl.SetAccessRuleProtection($true, $false)
$rule = [Security.AccessControl.FileSystemAccessRule]::new($identity.User, [Security.AccessControl.FileSystemRights]::FullControl, [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit', [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
[void]$acl.AddAccessRule($rule)
Set-Acl -LiteralPath $env:TINYSECURITY_NATIVE_DIRECTORY -AclObject $acl
";
    let output = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .env("TINYSECURITY_NATIVE_DIRECTORY", path)
        .output()?;
    if !output.status.success() {
        return Err("native audit namespace installer failed".into());
    }
    Ok(())
}

fn request(tail: u64) -> AuditedRequest2<CheckRequest> {
    AuditedRequest2 {
        request: CheckRequest {
            caller: CallerContext {
                agent: "agent".into(),
                call_id: format!("bearer private-native-operation-{tail}"),
                tier: AccessTier::Full,
                ..Default::default()
            },
            checks: vec![Check::LocalDiagnostic {}],
        },
        audit: AuditCorrelation2 {
            event_id: format!("{:032x}", tail + 1),
            expected_tail: tail,
            generation: 1,
        },
    }
}

pub(super) async fn verify(library: &Path) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_directory, path) = namespace()?;
    let bus = MemoryBus::new();
    let broker = Broker::new();
    let task = broker.spawn(bus.clone());
    let host = ModuleHost::new(broker);
    let client = Connection::connect(bus.connect().await?).await?;
    let mut audit = audit_config(true);
    audit.native_path = Some(path.to_str().ok_or("native fixture path encoding")?.into());
    audit.max_bytes = 2048;
    host.load_file_with_config(
        library,
        serde_json::to_value(ModuleConfig {
            trusted_host: client.unique_name().map(|peer| peer.as_str().to_owned()),
            audit: Some(audit),
            ..Default::default()
        })?,
    )?;
    let module = module_peer(&client).await?;
    let proxy = client.proxy(module.as_str(), names::OBJECT_PATH, names::INTERFACE)?;
    assert!(proxy.attestation().await?.is_some());
    let first: CheckAuditedResponse2 = proxy
        .call_confidential(names::methods::CHECK_AUDITED2, (request(0),))
        .await?;
    assert!(
        first.audit.permitted
            && first.audit.committed
            && matches!(first.decision.decisions[0].verdict, Verdict::Allow)
    );
    assert_eq!(
        proxy
            .call::<CheckAuditedResponse2>(names::methods::CHECK_AUDITED2, (request(0),))
            .await?,
        first
    );
    let journal = path.with_file_name("audit.journal");
    assert!(std::fs::metadata(&journal)?.len() > 0);
    assert!(
        std::fs::read(&journal)?
            .windows(b"private-native-operation".len())
            .all(|part| part != b"private-native-operation"),
        "the actual authority must contain sanitized data only"
    );
    #[cfg(windows)]
    verify_rename_denial(&proxy, &path).await?;
    host.shutdown(Duration::from_secs(1)).await;
    task.abort();
    println!("loaded required permission is backed by the actual restricted native journal");
    Ok(())
}

#[cfg(windows)]
async fn verify_rename_denial(
    proxy: &tinybus::Proxy,
    path: &Path,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    use std::os::windows::fs::OpenOptionsExt;
    let pin = OpenOptions::new().read(true).share_mode(3).open(path)?;
    let journal = path.with_file_name("audit.journal");
    let mut blocked = None;
    for tail in 1..16 {
        let before = std::fs::read(&journal)?;
        let response: CheckAuditedResponse2 = proxy
            .call(names::methods::CHECK_AUDITED2, (request(tail),))
            .await?;
        if !response.audit.permitted {
            assert!(!response.audit.committed && response.audit.receipt.is_none());
            assert!(
                response
                    .decision
                    .decisions
                    .iter()
                    .all(|decision| !matches!(decision.verdict, Verdict::Allow))
            );
            assert_eq!(
                std::fs::read(&journal)?,
                before,
                "required denied rename must not journal the candidate"
            );
            blocked = Some(tail);
            break;
        }
        assert!(response.audit.committed);
    }
    let tail = blocked.ok_or("required permission never reached blocked rotation")?;
    drop(pin);
    let permitted: CheckAuditedResponse2 = proxy
        .call(names::methods::CHECK_AUDITED2, (request(tail),))
        .await?;
    assert!(permitted.audit.permitted && permitted.audit.committed);
    let receipt = permitted
        .audit
        .receipt
        .as_ref()
        .ok_or("native exact receipt absent")?;
    assert_eq!(receipt.new_tail, tail + 1);
    assert_eq!(receipt.events[0].event_id, request(tail).audit.event_id);
    assert_eq!(
        proxy
            .call::<CheckAuditedResponse2>(names::methods::CHECK_AUDITED2, (request(tail),))
            .await?,
        permitted
    );
    Ok(())
}
