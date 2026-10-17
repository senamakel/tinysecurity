use super::*;
use crate::{Error, PrivacyMode};

fn request() -> PrivacyCheckRequest2 {
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
}

#[test]
fn a_privacy_request_is_bounded() {
    assert!(request().validate().is_ok());
    let mutations: [fn(&mut PrivacyCheckRequest2); 5] = [
        |r| r.destination_label = "x".repeat(MAX_PRIVACY_LABEL_BYTES + 1),
        |r| r.destination_label = "line\nbreak".into(),
        |r| {
            r.risk = Some(PrivacyRisk2 {
                level: PrivacyRiskLevel2::None,
                categories: vec!["c".into(); MAX_PRIVACY_CATEGORIES + 1],
            });
        },
        |r| {
            r.risk = Some(PrivacyRisk2 {
                level: PrivacyRiskLevel2::None,
                categories: vec!["x".repeat(MAX_PRIVACY_CATEGORY_BYTES + 1)],
            });
        },
        |r| {
            r.risk = Some(PrivacyRisk2 {
                level: PrivacyRiskLevel2::None,
                categories: vec![String::new()],
            });
        },
    ];
    for mutate in mutations {
        let mut bad = request();
        mutate(&mut bad);
        assert_eq!(bad.validate(), Err(Error::InvalidArguments));
    }
    let mut unassessed = request();
    unassessed.risk = None;
    assert!(unassessed.validate().is_ok());
}

#[test]
fn a_privacy_request_has_an_exact_wire_form() -> Result<(), serde_json::Error> {
    let wire = serde_json::to_value(request())?;
    assert_eq!(wire["privacy"], "sensitive");
    assert_eq!(wire["class"], "user_content");
    assert_eq!(wire["risk"]["level"], "low");
    assert_eq!(
        serde_json::from_value::<PrivacyCheckRequest2>(wire.clone())?,
        request()
    );
    let mut extra = wire;
    extra["extra"] = serde_json::json!(1);
    assert!(serde_json::from_value::<PrivacyCheckRequest2>(extra).is_err());
    for (class, wire) in [
        (PrivacyDataClass2::ControlPlane, "control_plane"),
        (PrivacyDataClass2::Metadata, "metadata"),
        (PrivacyDataClass2::UserContent, "user_content"),
    ] {
        assert_eq!(serde_json::to_value(class)?, wire);
    }
    assert_eq!(crate::names::methods::PRIVACY_CHECK2, "PrivacyCheck2");
    assert!(crate::names::METHODS.contains(&crate::names::methods::PRIVACY_CHECK2));
    Ok(())
}
