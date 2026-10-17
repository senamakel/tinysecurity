use super::*;

const MODES: [PrivacyMode; 3] = [
    PrivacyMode::LocalOnly,
    PrivacyMode::Standard,
    PrivacyMode::Sensitive,
];
const CLASSES: [PrivacyDataClass2; 3] = [
    PrivacyDataClass2::ControlPlane,
    PrivacyDataClass2::Metadata,
    PrivacyDataClass2::UserContent,
];

fn risk(level: PrivacyRiskLevel2, categories: &[&str]) -> Option<PrivacyRisk2> {
    Some(PrivacyRisk2 {
        level,
        categories: categories.iter().map(|c| (*c).to_owned()).collect(),
    })
}

fn request(
    privacy: PrivacyMode,
    external: bool,
    class: PrivacyDataClass2,
    risk: Option<PrivacyRisk2>,
) -> PrivacyCheckRequest2 {
    PrivacyCheckRequest2 {
        privacy,
        external,
        class,
        destination_label: "inference".into(),
        risk,
    }
}

/// Reference table written out independently of the implementation.
fn expected_denied(
    mode: &PrivacyMode,
    external: bool,
    class: PrivacyDataClass2,
    risk: &Option<PrivacyRisk2>,
) -> bool {
    if !external || class == PrivacyDataClass2::ControlPlane {
        return false;
    }
    match *mode {
        PrivacyMode::Standard => false,
        PrivacyMode::LocalOnly => true,
        PrivacyMode::Sensitive => {
            if class == PrivacyDataClass2::Metadata {
                return false;
            }
            match risk {
                None => true,
                Some(r) => {
                    matches!(r.level, PrivacyRiskLevel2::Medium | PrivacyRiskLevel2::High)
                        || r.categories.iter().any(|c| {
                            let c = c.to_lowercase();
                            [
                                "credential",
                                "secret",
                                "token",
                                "password",
                                "identifier",
                                "email",
                                "phone",
                                "ssn",
                                "card",
                            ]
                            .iter()
                            .any(|f| c.contains(f))
                        })
                }
            }
        }
    }
}

#[test]
fn full_truth_table_over_mode_external_class_and_risk() {
    let risks = [
        None,
        risk(PrivacyRiskLevel2::None, &[]),
        risk(PrivacyRiskLevel2::Low, &[]),
        risk(PrivacyRiskLevel2::Low, &["Email_Address"]),
        risk(PrivacyRiskLevel2::None, &["geo", "language"]),
        risk(PrivacyRiskLevel2::Medium, &[]),
        risk(PrivacyRiskLevel2::High, &["geo"]),
        risk(PrivacyRiskLevel2::None, &["CREDENTIAL"]),
    ];
    let mut rows = 0;
    for mode in MODES {
        for external in [false, true] {
            for class in CLASSES {
                for assessment in &risks {
                    let verdict = privacy_verdict(&request(
                        mode.clone(),
                        external,
                        class,
                        assessment.clone(),
                    ));
                    let want = if expected_denied(&mode, external, class, assessment) {
                        Verdict::Deny {
                            reason: DenialReason::Privacy,
                        }
                    } else {
                        Verdict::Allow
                    };
                    assert_eq!(
                        verdict, want,
                        "{mode:?} {external} {class:?} {assessment:?}"
                    );
                    rows += 1;
                }
            }
        }
    }
    assert_eq!(rows, 3 * 2 * 3 * 8);
}

#[test]
fn named_cases_pin_the_host_rule() {
    let denied = |mode: PrivacyMode, class, assessment| {
        privacy_verdict(&request(mode, true, class, assessment))
            == Verdict::Deny {
                reason: DenialReason::Privacy,
            }
    };
    assert!(denied(
        PrivacyMode::LocalOnly,
        PrivacyDataClass2::Metadata,
        None
    ));
    assert!(denied(
        PrivacyMode::LocalOnly,
        PrivacyDataClass2::UserContent,
        None
    ));
    assert!(!denied(
        PrivacyMode::LocalOnly,
        PrivacyDataClass2::ControlPlane,
        None
    ));
    assert!(!denied(
        PrivacyMode::Sensitive,
        PrivacyDataClass2::Metadata,
        None
    ));
    assert!(denied(
        PrivacyMode::Sensitive,
        PrivacyDataClass2::UserContent,
        None
    ));
    assert!(!denied(
        PrivacyMode::Sensitive,
        PrivacyDataClass2::UserContent,
        risk(PrivacyRiskLevel2::Low, &["language"])
    ));
    assert!(denied(
        PrivacyMode::Sensitive,
        PrivacyDataClass2::UserContent,
        risk(PrivacyRiskLevel2::Low, &["Phone"])
    ));
}
