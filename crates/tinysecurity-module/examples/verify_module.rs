//! Real native loader smoke test and reproducible policy hot-path timing.
use std::{
    io,
    path::PathBuf,
    time::{Duration, Instant},
};
use tinybus::{Connection, broker::Broker, module::ModuleHost, transport::memory::MemoryBus};
use tinysecurity_bus::{
    CallerContext, Check, CheckRequest, CheckResponse, Decision, DenialReason, EvaluateRequest,
    ModuleConfig, PolicyInfo, ToolCall, Verdict, names,
};
#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let bus = MemoryBus::new();
    let broker = Broker::new();
    let task = broker.spawn(bus.clone());
    let host = ModuleHost::new(broker);
    let config = serde_json::to_value(ModuleConfig::default())?;
    let info = match args.as_slice() {
        [path] => {
            let path = PathBuf::from(path);
            verify_bad_digests(&path)?;
            assert!(
                host.load_file(&path).is_err(),
                "missing init configuration must reject"
            );
            host.load_file_with_config(path, config)?
        }
        [url, archive, digest] => host.load_github_release(url, archive, Some(digest), config)?,
        _ => {
            return Err(io::Error::other(
                "usage: verify_module <native-path> OR <release-url> <archive> <sha256>",
            )
            .into());
        }
    };
    if info.name != "tinysecurity-module" {
        return Err(io::Error::other("unexpected module identity").into());
    }
    let client = Connection::connect(bus.connect().await?).await?;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if client
                .list_names()
                .await?
                .iter()
                .any(|n| n.as_str() == names::INTERFACE)
            {
                return tinybus::Result::Ok(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    let proxy = client.proxy(names::INTERFACE, names::OBJECT_PATH, names::INTERFACE)?;
    let caller = CallerContext {
        agent: "smoke".into(),
        call_id: "smoke-1".into(),
        ..Default::default()
    };
    let checks = CheckRequest {
        caller: caller.clone(),
        checks: vec![
            Check::LocalDiagnostic {},
            Check::Path {
                path: native_protected_path().to_string_lossy().into_owned(),
                write: false,
            },
        ],
    };
    let response: CheckResponse = proxy.call(names::methods::CHECK, (checks.clone(),)).await?;
    assert_eq!(response.decisions[0].verdict, Verdict::Allow);
    assert_eq!(
        response.decisions[1].verdict,
        Verdict::Deny {
            reason: DenialReason::Floor
        }
    );
    assert!(
        proxy
            .call::<Decision>(names::methods::EVALUATE, ())
            .await
            .is_err()
    );
    assert!(
        proxy
            .call::<Decision>(names::methods::DECIDE, ())
            .await
            .is_err()
    );
    let (path_scope, fixture) = register_native_scope(&proxy).await?;
    verify_reconfiguration(&host, &proxy, &info.name).await?;
    verify_native_scope(&proxy, path_scope, fixture.path()).await?;
    let evaluate = EvaluateRequest {
        caller,
        call: ToolCall {
            tool: "local_diagnostic".into(),
            arguments_json: "{}".into(),
            checks: vec![Check::LocalDiagnostic {}],
        },
    };
    benchmark(&proxy, &evaluate, &checks).await?;
    host.shutdown(Duration::from_secs(1)).await;
    assert!(
        host.reinitialize(&info.name, serde_json::to_value(ModuleConfig::default())?)
            .await
            .is_err()
    );
    task.abort();
    Ok(())
}

async fn benchmark(
    proxy: &tinybus::Proxy,
    evaluate: &EvaluateRequest,
    checks: &CheckRequest,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut evaluate_times = Vec::new();
    let mut check_times = Vec::new();
    for _ in 0..500 {
        let start = Instant::now();
        let decision: Decision = proxy
            .call(names::methods::EVALUATE, (evaluate.clone(),))
            .await?;
        assert_eq!(decision.verdict, Verdict::Allow);
        evaluate_times.push(start.elapsed());
        let start = Instant::now();
        let _: CheckResponse = proxy.call(names::methods::CHECK, (checks.clone(),)).await?;
        check_times.push(start.elapsed());
    }
    evaluate_times.sort_unstable();
    check_times.sort_unstable();
    println!("native module allow/deny, malformed args and failed/accepted reinit verified");
    println!(
        "500 samples per method, one Evaluate bus call/sample, one Check bus call/sample for two checks"
    );
    println!(
        "Evaluate p50={:?} p99={:?}; Check p50={:?} p99={:?}",
        evaluate_times[250], evaluate_times[494], check_times[250], check_times[494]
    );
    Ok(())
}

fn verify_bad_digests(
    path: &std::path::Path,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    let directory =
        PathBuf::from("target").join(format!("native-admission-{}", std::process::id()));
    std::fs::create_dir_all(&directory)?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("native library name is not UTF-8")?;
    let copy = directory.join(name);
    std::fs::copy(path, &copy)?;
    let allowlist = directory.join("modules.toml");
    std::fs::write(&allowlist, format!("\"{name}\" = \"{}\"\n", "0".repeat(64)))?;
    let host = ModuleHost::new(Broker::new());
    assert!(
        host.load_file_with_config(&copy, serde_json::to_value(ModuleConfig::default())?)
            .is_err()
    );
    let digest = tinybus::module::sha256_file(&copy)?;
    std::fs::write(&allowlist, format!("\"{name}\" = \"{digest}\"\n"))?;
    std::fs::OpenOptions::new()
        .append(true)
        .open(&copy)?
        .write_all(b"tampered")?;
    assert!(
        host.load_file_with_config(&copy, serde_json::to_value(ModuleConfig::default())?)
            .is_err()
    );
    std::fs::remove_dir_all(directory)?;
    Ok(())
}

async fn verify_reconfiguration(
    host: &ModuleHost,
    proxy: &tinybus::Proxy,
    module: &str,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let before: PolicyInfo = proxy.call(names::methods::POLICY_INFO, ()).await?;
    let invalid = ModuleConfig {
        contract_version: (9, 0),
        ..Default::default()
    };
    assert!(
        host.reinitialize(module, serde_json::to_value(invalid)?)
            .await
            .is_err()
    );
    let unchanged: PolicyInfo = proxy.call(names::methods::POLICY_INFO, ()).await?;
    assert_eq!(before, unchanged);
    host.reinitialize(module, serde_json::to_value(ModuleConfig::default())?)
        .await?;
    let after: PolicyInfo = proxy.call(names::methods::POLICY_INFO, ()).await?;
    assert_eq!(after.generation, before.generation + 1);
    Ok(())
}

async fn register_native_scope(
    proxy: &tinybus::Proxy,
) -> std::result::Result<
    (tinysecurity_bus::PathPolicyId, tempfile::TempDir),
    Box<dyn std::error::Error>,
> {
    let fixture = tempfile::tempdir()?;
    std::fs::write(fixture.path().join("file"), "native scope fixture")?;
    let root = fixture.path().canonicalize()?;
    let policy = tinysecurity_bus::PathPolicy {
        enabled: true,
        workspace_only: true,
        workspace_dir: root.clone(),
        action_dir: root,
        home_dir: None,
        forbidden_paths: vec![],
        trusted_roots: vec![],
        reserved_paths: vec![],
        reserved_prefixes: vec![],
        readonly_paths: vec![],
        reserved_names: vec![],
    };
    let id = proxy
        .call(names::methods::REGISTER_PATH_POLICY, (policy,))
        .await?;
    Ok((id, fixture))
}
async fn verify_native_scope(
    proxy: &tinybus::Proxy,
    policy_id: tinysecurity_bus::PathPolicyId,
    root: &std::path::Path,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    use tinysecurity_bus::{
        PathCheckKind, PathCheckRequest, PathValidationRequest, PathValidationResult,
    };
    let request = PathValidationRequest {
        policy_id: policy_id.clone(),
        path: "file".into(),
    };
    let read: PathValidationResult = proxy
        .call(names::methods::VALIDATE_PATH, (request,))
        .await?;
    assert_eq!(
        read,
        PathValidationResult::Allowed {
            resolved: root.canonicalize()?.join("file")
        }
    );
    let write: PathValidationResult = proxy
        .call(
            names::methods::VALIDATE_PARENT,
            (PathValidationRequest {
                policy_id: policy_id.clone(),
                path: "prospective/path/file".into(),
            },),
        )
        .await?;
    assert_eq!(
        write,
        PathValidationResult::Allowed {
            resolved: root.canonicalize()?.join("prospective/path/file")
        }
    );
    let protected: bool = proxy
        .call(
            names::methods::CHECK_PATH,
            (PathCheckRequest {
                policy_id,
                path: native_protected_path(),
                kind: PathCheckKind::Protected,
            },),
        )
        .await?;
    assert!(protected);
    println!("native immutable path scope survives accepted SDK reinitialization");
    Ok(())
}

fn native_protected_path() -> PathBuf {
    #[cfg(windows)]
    {
        std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
            .join("System32")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/etc/passwd")
    }
}
