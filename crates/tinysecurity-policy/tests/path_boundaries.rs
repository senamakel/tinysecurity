//! Regression coverage for host-resolved paths and native system roots.
use tinysecurity_policy::*;

fn request(path: &str) -> CheckRequest {
    CheckRequest {
        caller: CallerContext {
            agent: "operator".into(),
            call_id: "path-check".into(),
            tier: AccessTier::Full,
            ..Default::default()
        },
        checks: vec![Check::Path {
            path: path.into(),
            write: true,
        }],
    }
}

#[test]
fn relative_operation_paths_are_rejected_in_both_policy_modes()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let fixture = tempfile::tempdir()?;
    let action = fixture.path().join("action");
    let workspace = fixture.path().join("state");
    std::fs::create_dir_all(&action)?;
    std::fs::create_dir_all(&workspace)?;
    for enabled in [false, true] {
        let policy = Policy::new(ModuleConfig {
            policy: PolicyConfig {
                enabled,
                action_dir: action.to_string_lossy().into(),
                workspace_dir: workspace.to_string_lossy().into(),
                ..Default::default()
            },
            ..Default::default()
        })?;
        for path in ["passwd", "./passwd", "nested/file"] {
            assert_eq!(
                policy.check(&request(path))?.decisions[0].verdict,
                Verdict::Deny {
                    reason: DenialReason::PathResolution
                },
                "enabled={enabled}, path={path}"
            );
        }
    }
    Ok(())
}

#[test]
fn disabled_policy_protects_executable_and_library_roots_on_every_platform()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let policy = Policy::new(ModuleConfig::default())?;
    for path in [
        "/bin/tool",
        "/sbin/tool",
        "/lib/library",
        "/lib64/library",
        "/usr/bin/tool",
        "/usr/sbin/tool",
        "/usr/lib/library",
        "/usr/lib64/library",
        "/usr/local/bin/tool",
        "/usr/local/lib/library",
        "/Library/Frameworks/library",
        "D:\\Windows\\System32\\config",
        "Z:\\Program Files\\tool",
        "E:\\Program Files (x86)\\tool",
        "F:\\ProgramData\\state",
        "\\\\?\\D:\\Windows\\System32\\config",
        "\\??\\E:\\Windows\\System32",
        "\\Device\\HarddiskVolume2\\Windows\\System32",
        "\\\\?\\Volume{fixture}\\Windows\\System32",
        "D:\\Windows.\\System32",
        "E:\\Windows:stream",
    ] {
        assert_eq!(
            policy.check(&request(path))?.decisions[0].verdict,
            Verdict::Deny {
                reason: DenialReason::Floor
            },
            "{path}"
        );
    }
    Ok(())
}

#[test]
fn disabled_policy_denies_device_roots_without_opening_devices()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let policy = Policy::new(ModuleConfig::default())?;
    for path in ["/dev", "/dev/sda", "/dev/null", "/dev/mapper/system"] {
        assert_eq!(
            policy.check(&request(path))?.decisions[0].verdict,
            Verdict::Deny {
                reason: DenialReason::Floor
            },
            "{path}"
        );
    }
    Ok(())
}

#[test]
fn every_windows_drive_prefix_preserves_system_and_credential_floors()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let policy = Policy::new(ModuleConfig::default())?;
    // Pure lexical checks do not require a mounted Windows drive on the runner.
    for drive in 'A'..='Z' {
        for suffix in [
            "Windows\\System32\\config",
            "Program Files\\tool",
            "Program Files (x86)\\tool",
            "ProgramData\\state",
            "Users\\me\\.aws\\credentials",
        ] {
            let path = format!("{drive}:\\{suffix}");
            assert_eq!(
                policy.check(&request(&path))?.decisions[0].verdict,
                Verdict::Deny {
                    reason: DenialReason::Floor
                },
                "{path}"
            );
        }
    }
    Ok(())
}
