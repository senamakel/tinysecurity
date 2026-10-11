use super::*;

#[test]
fn windows_approval_namespace_preserves_drive_path_and_opens_restricted_sink() {
    use std::path::{Component, Prefix};

    let Ok((_directory, root)) = create() else {
        panic!("approval namespace installer must succeed");
    };
    assert!(
        matches!(
            root.components().next(),
            Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_))
        ),
        "approval namespace must preserve an ordinary drive path"
    );
    assert!(
        tinysecurity::audit::JsonlSink::open(&root.join("audit"), 2048, 3).is_ok(),
        "approval namespace must pass actual restricted engine open"
    );
}
