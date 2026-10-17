//! Golden wire fixtures for contract 1.22 flow trust, scored prompt scanning and
//! the approval origin classes.
use serde_json::Value;
use tinysecurity_bus::*;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn fixtures() -> std::result::Result<Value, serde_json::Error> {
    serde_json::from_str(include_str!("fixtures/v1_22_approval_scan.json"))
}
macro_rules! golden {
    ($type:ty, $key:literal, $name:ident) => {
        #[test]
        fn $name() -> TestResult {
            let v = fixtures()?[$key].clone();
            let decoded: $type = serde_json::from_value(v.clone())?;
            assert_eq!(serde_json::to_value(&decoded)?, v);
            assert_eq!(
                serde_json::from_str::<$type>(&serde_json::to_string(&decoded)?)?,
                decoded
            );
            Ok(())
        }
    };
}
golden!(GrantFlowToolRequest2, "GrantFlowToolRequest2", grant_wire);
golden!(
    RevokeFlowToolRequest2,
    "RevokeFlowToolRequest2",
    revoke_wire
);
golden!(ListFlowTrustRequest2, "ListFlowTrustRequest2", list_wire);
golden!(
    ListFlowTrustRequest2,
    "ListFlowTrustRequest2All",
    list_all_wire
);
golden!(FlowTrustList2, "FlowTrustList2", list_response_wire);
golden!(FlowTrustReceipt2, "FlowTrustReceipt2", receipt_wire);
golden!(
    FlowTrustReceipt2,
    "FlowTrustReceiptAbsent",
    receipt_absent_wire
);
golden!(
    ScanPromptScoredRequest2,
    "ScanPromptScoredRequest2",
    scan_request_wire
);
golden!(
    ScanPromptScoredResponse2,
    "ScanPromptScoredResponse2",
    scan_response_wire
);

#[test]
fn origin_classes_keep_their_wire_names_and_older_origins_are_unchanged() -> TestResult {
    let names: Vec<Origin> = serde_json::from_value(fixtures()?["Origin"].clone())?;
    assert_eq!(
        names,
        vec![
            Origin::Operator,
            Origin::Copilot,
            Origin::SubAgent,
            Origin::Cron,
            Origin::Saas,
            Origin::TrustedAutomation,
            Origin::LocalOperator,
            Origin::Unlabelled,
        ]
    );
    assert_eq!(serde_json::to_value(&names)?, fixtures()?["Origin"]);
    assert!(serde_json::from_str::<Origin>("\"unknown_origin\"").is_err());
    Ok(())
}

#[test]
fn new_requests_reject_unknown_fields_and_new_members_are_advertised() -> TestResult {
    let mut v = fixtures()?["GrantFlowToolRequest2"].clone();
    v["wildcard"] = true.into();
    assert!(serde_json::from_value::<GrantFlowToolRequest2>(v).is_err());
    let mut v = fixtures()?["ScanPromptScoredRequest2"].clone();
    v["extra"] = 1.into();
    assert!(serde_json::from_value::<ScanPromptScoredRequest2>(v).is_err());
    for member in [
        names::methods::GRANT_FLOW_TOOL2,
        names::methods::REVOKE_FLOW_TOOL2,
        names::methods::LIST_FLOW_TRUST2,
        names::methods::SCAN_PROMPT2,
    ] {
        assert!(names::METHODS.contains(&member), "{member} not advertised");
    }
    assert_eq!(names::methods::GRANT_FLOW_TOOL2, "GrantFlowTool2");
    assert_eq!(names::methods::SCAN_PROMPT2, "ScanPrompt2");
    Ok(())
}
