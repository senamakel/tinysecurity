//! Golden wire fixtures for the contract 1.22 policy and egress members.
use tinysecurity_bus::*;

fn fixtures() -> std::result::Result<serde_json::Value, serde_json::Error> {
    serde_json::from_str(include_str!("fixtures/v1_22.json"))
}

macro_rules! golden {
    ($name:ident, $type:ty, $value:expr) => {
        #[test]
        fn $name() -> std::result::Result<(), serde_json::Error> {
            let fixture = fixtures()?[stringify!($type)].clone();
            let value: $type = $value;
            assert_eq!(serde_json::to_value(&value)?, fixture);
            assert_eq!(serde_json::from_value::<$type>(fixture)?, value);
            Ok(())
        }
    };
}

golden!(
    path_batch_request,
    PathBatchRequest2,
    PathBatchRequest2 {
        policy_id: PathPolicyId("path-scope-0".into()),
        kind: PathCheckKind::ResolvedWrite,
        paths: vec!["/work/a.txt".into(), "/work/b.txt".into()],
    }
);
golden!(
    path_batch_response,
    PathBatchResponse2,
    PathBatchResponse2 {
        allowed: vec![true, false]
    }
);
golden!(
    protected_path_request,
    ProtectedPathRequest2,
    ProtectedPathRequest2 {
        paths: vec!["/home/u/.ssh/id_rsa".into()]
    }
);
golden!(
    protected_path_response,
    ProtectedPathResponse2,
    ProtectedPathResponse2 {
        protected: vec![true]
    }
);
golden!(
    protected_floor,
    ProtectedFloor2,
    ProtectedFloor2 {
        components: vec![".ssh".into()],
        files: vec![".netrc".into()],
        pairs: vec![[".docker".into(), "config.json".into()]],
        prefixes: vec!["/etc".into()],
    }
);
golden!(
    budget_request,
    BudgetRequest2,
    BudgetRequest2 {
        command_policy: CommandPolicyId("command-scope-0".into())
    }
);
golden!(
    budget_rate_limited,
    BudgetDecision2,
    BudgetDecision2::RateLimited { max_per_hour: 20 }
);
golden!(
    host_action_class_request,
    HostActionClassRequest2,
    HostActionClassRequest2 {
        permission: ToolPermission::Write,
        external_effect: true,
    }
);
golden!(
    host_action_class_response,
    HostActionClassResponse2,
    HostActionClassResponse2 {
        class: CommandClass::Network
    }
);
golden!(
    privacy_check_request,
    PrivacyCheckRequest2,
    PrivacyCheckRequest2 {
        privacy: PrivacyMode::Sensitive,
        external: true,
        class: PrivacyDataClass2::UserContent,
        destination_label: "openrouter".into(),
        risk: Some(PrivacyRisk2 {
            level: PrivacyRiskLevel2::Low,
            categories: vec!["email".into()],
        }),
    }
);
golden!(
    privacy_check_response,
    PrivacyCheckResponse2,
    PrivacyCheckResponse2 {
        decision: Decision {
            generation: 3,
            verdict: Verdict::Deny {
                reason: DenialReason::Privacy
            },
            cacheable: false,
        }
    }
);

#[test]
fn every_member_is_advertised_once() {
    for name in [
        names::methods::CHECK_PATHS2,
        names::methods::PROTECTED_PATH2,
        names::methods::PROTECTED_FLOOR2,
        names::methods::SPEND_ACTION2,
        names::methods::PEEK_BUDGET2,
        names::methods::CLASSIFY_HOST_ACTION2,
        names::methods::PRIVACY_CHECK2,
    ] {
        assert_eq!(names::METHODS.iter().filter(|m| **m == name).count(), 1);
    }
}
