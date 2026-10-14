use super::*;

fn policy(action: &str, entries: &[&str]) -> PolicyConfig {
    PolicyConfig {
        enabled: true,
        action_dir: action.into(),
        workspace_dir: action.into(),
        allowed_commands: vec![],
        forbidden_paths: entries.iter().map(|e| (*e).into()).collect(),
    }
}

fn effective(entries: &[&str], home: Option<&str>) -> Result<Vec<String>> {
    effective_forbidden(&policy("/work/action", entries), home.map(Path::new))
}

#[test]
fn absolute_entries_pass_through_unchanged_and_deduplicate() {
    assert_eq!(
        effective(&["/work/secret", "/work/secret", "/work/other"], None),
        Ok(vec!["/work/secret".into(), "/work/other".into()])
    );
}

#[test]
fn tilde_entries_expand_against_the_registered_home() {
    assert_eq!(
        effective(&["~/.config/app", "~", "~\\win"], Some("/home/u")),
        Ok(vec![
            "/home/u/.config/app".into(),
            "/home/u".into(),
            "/home/u/win".into()
        ])
    );
}

#[test]
fn tilde_without_a_registered_home_or_with_a_user_form_is_rejected() {
    assert_eq!(effective(&["~/x"], None), Err(Error::InvalidArguments));
    assert_eq!(effective(&["~"], None), Err(Error::InvalidArguments));
    assert_eq!(
        effective(&["~other/x"], Some("/home/u")),
        Err(Error::InvalidArguments)
    );
}

#[test]
fn relative_entries_resolve_against_the_action_dir() {
    assert_eq!(
        effective(&["private", "a/b"], None),
        Ok(vec![
            "/work/action/private".into(),
            "/work/action/a/b".into()
        ])
    );
}

#[test]
fn relative_entries_cannot_be_anchored_without_an_absolute_action_dir() {
    assert_eq!(
        effective_forbidden(&policy("relative-action", &["private"]), None),
        Err(Error::InvalidArguments)
    );
    // Absolute entries do not need an anchor.
    assert_eq!(
        effective_forbidden(&policy("relative-action", &["/abs"]), None),
        Ok(vec!["/abs".into()])
    );
}

#[cfg(windows)]
#[test]
fn rooted_entries_without_a_drive_are_refused_on_windows() {
    assert_eq!(effective(&["\\rooted"], None), Err(Error::InvalidArguments));
}

#[test]
fn traversal_nul_and_empty_entries_are_rejected_not_dropped() {
    for entry in ["", "../up", "a/../b", "/abs/../x", "~/../x", "nul\0byte"] {
        assert_eq!(
            effective(&[entry], Some("/home/u")),
            Err(Error::InvalidArguments),
            "{entry:?}"
        );
    }
}

#[test]
fn entries_inside_the_unconditional_floor_are_redundant_noops() {
    assert_eq!(
        effective(
            &[
                "/etc/passwd",
                "~/.ssh",
                "~/.aws/credentials",
                "/work/secret"
            ],
            Some("/home/u")
        ),
        Ok(vec!["/work/secret".into()])
    );
}
