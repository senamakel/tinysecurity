use super::*;

// Read-only diagnostics for native CI. Never print a path, SID or descriptor.
pub(crate) fn diagnose(path: &Path) {
    let Ok(user) = identity() else {
        eprintln!("audit-stage=identity result=denied");
        return;
    };
    eprintln!("audit-stage=identity result=ok");
    let mut current = PathBuf::new();
    let mut pins = Vec::new();
    let mut ordinal = 0;
    for component in path.components() {
        current.push(component.as_os_str());
        if matches!(component, Component::Prefix(_)) {
            continue;
        }
        if component == Component::RootDir {
            let Some(root) = current.to_str() else {
                eprintln!("audit-stage=volume result=invalid-encoding");
                return;
            };
            eprintln!("audit-stage=volume result={:?}", verify_volume(root));
        }
        let handle = match OpenOptions::new()
            .access_mode(READ_CONTROL_ATTRIBUTES)
            .share_mode(3)
            .custom_flags(PIN_DIRECTORY)
            .open(&current)
        {
            Ok(handle) => handle,
            Err(error) => {
                eprintln!(
                    "audit-stage=pin ancestor={ordinal} errno={:?}",
                    error.raw_os_error()
                );
                return;
            }
        };
        inspect(&handle, &user, ordinal);
        eprintln!(
            "audit-stage=ancestor ancestor={ordinal} result={:?}",
            verify_ancestor(&handle, &user)
        );
        pins.push(handle);
        ordinal += 1;
    }
    if let Some(last) = pins.last() {
        eprintln!(
            "audit-stage=restricted-directory result={:?}",
            verify_restricted(last, &user, true)
        );
    }
    for (stage, name) in [
        ("existing-lock", "audit.lock"),
        ("existing-journal", "audit.journal"),
    ] {
        match OpenOptions::new()
            .access_mode(READ_CONTROL_ATTRIBUTES)
            .share_mode(3)
            .custom_flags(OPEN_REPARSE)
            .open(path.join(name))
        {
            Ok(file) => {
                inspect(&file, &user, ordinal);
                eprintln!(
                    "audit-stage={stage} result={:?}",
                    verify_restricted(&file, &user, false)
                );
            }
            Err(error) => eprintln!("audit-stage={stage} errno={:?}", error.raw_os_error()),
        }
    }
}

fn inspect(file: &File, user: &str, ordinal: usize) {
    match file.metadata() {
        Ok(metadata) => eprintln!(
            "audit-stage=metadata ancestor={ordinal} attributes={} directory={}",
            metadata.file_attributes(),
            metadata.is_dir()
        ),
        Err(error) => eprintln!(
            "audit-stage=metadata ancestor={ordinal} errno={:?}",
            error.raw_os_error()
        ),
    }
    let sd = match wrappers::GetSecurityInfo(
        file,
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Owner | SecurityInformation::Dacl,
    ) {
        Ok(sd) => sd,
        Err(error) => {
            eprintln!(
                "audit-stage=descriptor ancestor={ordinal} errno={:?}",
                error.raw_os_error()
            );
            return;
        }
    };
    let owner = sd.owner().and_then(|sid| sid_text(sid).ok());
    eprintln!(
        "audit-stage=owner ancestor={ordinal} class={}",
        principal_class(owner.as_deref(), user)
    );
    if let Some(acl) = sd.dacl() {
        eprintln!("audit-stage=dacl ancestor={ordinal} count={}", acl.len());
        for index in 0..acl.len() {
            if let Some(ace) = acl.get_ace(index) {
                let sid = ace.sid().and_then(|sid| sid_text(sid).ok());
                eprintln!(
                    "audit-stage=ace ancestor={ordinal} index={index} class={} type={} flags={} mask={} mutation={}",
                    principal_class(sid.as_deref(), user),
                    ace.ace_type() as u8,
                    ace.flags().bits(),
                    ace.mask().bits(),
                    ace.mask().bits() & 0x500d_0152
                );
            }
        }
    } else {
        eprintln!("audit-stage=dacl ancestor={ordinal} result=absent");
    }
    match sd.as_sddl() {
        Ok(sddl) => {
            let Ok(sddl) = sddl.into_string() else {
                eprintln!("audit-stage=dacl-control ancestor={ordinal} result=invalid-encoding");
                return;
            };
            let flags = sddl
                .split("D:")
                .nth(1)
                .and_then(|dacl| dacl.split('(').next())
                .unwrap_or("");
            eprintln!(
                "audit-stage=dacl-control ancestor={ordinal} flags={}",
                control_flags(flags)
            );
        }
        Err(error) => eprintln!(
            "audit-stage=dacl-control ancestor={ordinal} errno={:?}",
            error.raw_os_error()
        ),
    }
}

fn principal_class(sid: Option<&str>, user: &str) -> u8 {
    match sid {
        Some(sid) if sid == user => 1,
        Some("S-1-5-18") => 2,
        Some("S-1-5-32-544") => 3,
        Some(TRUSTED_INSTALLER) => 4,
        Some(_) => 5,
        None => 0,
    }
}

fn control_flags(mut flags: &str) -> u8 {
    let mut bits = 0;
    while !flags.is_empty() {
        if let Some(rest) = flags.strip_prefix('P') {
            bits |= 1;
            flags = rest;
        } else if let Some(rest) = flags.strip_prefix("AI") {
            bits |= 2;
            flags = rest;
        } else if let Some(rest) = flags.strip_prefix("AR") {
            bits |= 4;
            flags = rest;
        } else {
            return bits | 128;
        }
    }
    bits
}

#[test]
fn windows_diagnostic_classification_never_retains_identity_or_unknown_flag_text() {
    assert_eq!(
        principal_class(Some("private identity"), "current identity"),
        5
    );
    assert_eq!(principal_class(None, "current identity"), 0);
    assert_eq!(control_flags("PAI"), 3);
    assert_eq!(control_flags("PARAI"), 7);
    assert_eq!(control_flags("Pprivate payload"), 129);
}
