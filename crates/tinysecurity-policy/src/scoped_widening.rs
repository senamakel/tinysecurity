//! Authority increases between two policies of one subject.
use crate::ScopedPolicy;
use std::path::Path;
use tinysecurity_bus::{
    CommandAutonomy, PathAccess, PrivacyMode, ToolRuleEffect, Widening, WideningKind,
};

const fn autonomy(value: CommandAutonomy) -> u8 {
    match value {
        CommandAutonomy::ReadOnly => 0,
        CommandAutonomy::Supervised => 1,
        CommandAutonomy::Full => 2,
    }
}

/// Higher is stricter.
const fn privacy(value: &PrivacyMode) -> u8 {
    match value {
        PrivacyMode::Standard => 1,
        PrivacyMode::Sensitive => 2,
        PrivacyMode::LocalOnly => 3,
    }
}

const fn access(value: PathAccess) -> u8 {
    match value {
        PathAccess::ReadOnly => 0,
        PathAccess::ReadWrite => 1,
    }
}

fn push(out: &mut Vec<Widening>, kind: WideningKind, subject: impl Into<String>) {
    out.push(Widening {
        kind,
        subject: subject.into(),
    });
}

/// Every authority the replacement grants that the previous policy did not.
pub(crate) fn widenings(old: &ScopedPolicy, new: &ScopedPolicy) -> Vec<Widening> {
    let mut out = Vec::new();
    boundaries(old, new, &mut out);
    roots(old, new, &mut out);
    hosts_and_tools(old, new, &mut out);
    commands(old, new, &mut out);
    authority(old, new, &mut out);
    out.dedup();
    out
}

fn boundaries(old: &ScopedPolicy, new: &ScopedPolicy, out: &mut Vec<Widening>) {
    let (os, ns) = (&old.registered().settings, &new.registered().settings);
    if os.policy.enabled && !ns.policy.enabled {
        push(out, WideningKind::Boundary, "policy_disabled");
    }
    if privacy(&ns.privacy) < privacy(&os.privacy) {
        push(out, WideningKind::Boundary, "privacy_loosened");
    }
    if old.paths().enabled && !new.paths().enabled {
        push(out, WideningKind::Boundary, "path_scope_disabled");
    }
}

fn roots(old: &ScopedPolicy, new: &ScopedPolicy, out: &mut Vec<Widening>) {
    let (os, ns) = (&old.registered().settings, &new.registered().settings);
    let (op, np) = (&**old.paths(), &**new.paths());
    // Base settings decide which roots are permitted or reserved for the subject.
    let (oa, na) = (
        Path::new(&os.policy.action_dir),
        Path::new(&ns.policy.action_dir),
    );
    if !na.starts_with(oa) {
        push(
            out,
            WideningKind::Root,
            format!("action_dir:{}", na.display()),
        );
    }
    if os.policy.workspace_dir != ns.policy.workspace_dir {
        push(out, WideningKind::Root, "workspace_dir");
    }
    if op.workspace_only && !np.workspace_only {
        push(out, WideningKind::Root, "workspace_only");
    }
    let covered = |path: &Path, wanted: u8| {
        op.trusted_roots
            .iter()
            .any(|r| path.starts_with(&r.path) && access(r.access) >= wanted)
            || path.starts_with(&op.action_dir)
    };
    for root in &np.trusted_roots {
        if !covered(&root.path, access(root.access)) {
            push(out, WideningKind::Root, root.path.display().to_string());
        }
    }
    if !covered(&np.action_dir, 1) {
        push(out, WideningKind::Root, np.action_dir.display().to_string());
    }
    for forbidden in &op.forbidden_paths {
        if !np.forbidden_paths.contains(forbidden) {
            push(out, WideningKind::Root, format!("forbidden:{forbidden}"));
        }
    }
    // Compare the folded roots: `~`, relative and floor spellings are equivalent.
    for forbidden in &old.effective_policy().forbidden_paths {
        if !new.effective_policy().forbidden_paths.contains(forbidden) {
            push(out, WideningKind::Root, format!("forbidden:{forbidden}"));
        }
    }
    for reserved in &op.reserved_paths {
        let kept = np
            .reserved_paths
            .iter()
            .any(|r| r.path == reserved.path && r.exceptions.len() <= reserved.exceptions.len());
        if !kept {
            push(
                out,
                WideningKind::Root,
                format!("reserved:{}", reserved.path.display()),
            );
        }
    }
    for readonly in &op.readonly_paths {
        if !np.readonly_paths.contains(readonly) {
            push(
                out,
                WideningKind::Root,
                format!("readonly:{}", readonly.display()),
            );
        }
    }
}

fn hosts_and_tools(old: &ScopedPolicy, new: &ScopedPolicy, out: &mut Vec<Widening>) {
    let (o, n) = (old.registered(), new.registered());
    for host in &n.settings.egress_hosts {
        if !o.settings.egress_hosts.contains(host) {
            let name = format!("{}://{}:{}", host.scheme, host.hostname, host.port);
            push(out, WideningKind::Host, name);
        }
    }
    let permitted = |rules: &[tinysecurity_bus::ToolRule], tool: &str| {
        !rules
            .iter()
            .any(|r| r.tool == tool && r.effect == ToolRuleEffect::Deny)
            && (!rules.iter().any(|r| r.effect == ToolRuleEffect::Allow)
                || rules
                    .iter()
                    .any(|r| r.tool == tool && r.effect == ToolRuleEffect::Allow))
    };
    let mut seen = Vec::new();
    for tool in o
        .tool_rules
        .iter()
        .chain(&n.tool_rules)
        .map(|r| r.tool.as_str())
    {
        if seen.contains(&tool) {
            continue;
        }
        seen.push(tool);
        if !permitted(&o.tool_rules, tool) && permitted(&n.tool_rules, tool) {
            push(out, WideningKind::Tool, tool);
        }
    }
    let allowlist = |rules: &[tinysecurity_bus::ToolRule]| {
        rules.iter().any(|r| r.effect == ToolRuleEffect::Allow)
    };
    if allowlist(&o.tool_rules) && !allowlist(&n.tool_rules) {
        push(out, WideningKind::Tool, "*");
    }
}

fn commands(old: &ScopedPolicy, new: &ScopedPolicy, out: &mut Vec<Widening>) {
    let (os, ns) = (&old.registered().settings, &new.registered().settings);
    for command in &ns.policy.allowed_commands {
        if !os.policy.allowed_commands.contains(command) {
            push(out, WideningKind::Class, format!("command:{command}"));
        }
    }
    let (oc, nc) = (old.command_policy(), new.command_policy());
    // A different command scope id is not itself a widening. Only what the new
    // scope grants beyond the old one is: the comparisons below cover context,
    // enforcement, autonomy, mode, budget size, approvals and allowlist. The
    // fresh hourly ledger is accepted when the budget is not larger.
    if oc.action_dir != nc.action_dir
        || oc.home_dir != nc.home_dir
        || oc.shell_dialect != nc.shell_dialect
    {
        push(out, WideningKind::Class, "command_context");
    }
    if oc.enabled && !nc.enabled {
        push(out, WideningKind::Boundary, "command_policy_disabled");
    }
    let flags = [
        (autonomy(nc.autonomy) > autonomy(oc.autonomy), "autonomy"),
        (nc.execution_mode != oc.execution_mode, "execution_mode"),
        (nc.max_actions_per_hour > oc.max_actions_per_hour, "budget"),
        (
            oc.require_approval_for_medium_risk && !nc.require_approval_for_medium_risk,
            "medium_risk_approval",
        ),
        (
            oc.block_high_risk_commands && !nc.block_high_risk_commands,
            "high_risk_block",
        ),
    ];
    for (widened, name) in flags {
        if widened {
            push(out, WideningKind::Class, name);
        }
    }
    for command in &nc.allowed_commands {
        if !oc.allowed_commands.contains(command) {
            push(out, WideningKind::Class, format!("command:{command}"));
        }
    }
    if !os.command_classes.is_empty() {
        if ns.command_classes.is_empty() {
            push(out, WideningKind::Class, "all_classes");
        }
        for class in &ns.command_classes {
            if !os.command_classes.contains(class) {
                push(out, WideningKind::Class, format!("class:{class:?}"));
            }
        }
    }
}

fn authority(old: &ScopedPolicy, new: &ScopedPolicy, out: &mut Vec<Widening>) {
    let (os, ns) = (&old.registered().settings, &new.registered().settings);
    for origin in &ns.auto_origins {
        if !os.auto_origins.contains(origin) {
            push(out, WideningKind::AutoOrigin, format!("{origin:?}"));
        }
    }
    if !os.judge_enabled && ns.judge_enabled {
        push(out, WideningKind::Judge, "enabled");
    }
}
