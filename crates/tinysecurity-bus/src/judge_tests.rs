use super::*;
#[test]
fn evidence_wire_rejects_unbounded_scores_unknown_fields_and_question_changes()
-> Result<(), Box<dyn std::error::Error>> {
    let valid = JudgeEvidence2 {
        outcome: JudgeOutcome2::Qualified,
        question_ids: ["intent", "reversible", "exfiltrate"].map(str::to_owned),
        scores_millionths: Some([900_000, 900_000, 100_000]),
        thresholds: crate::JudgeThresholds {
            intent: 900,
            reversible: 900,
            exfiltrate: 100,
        },
        configuration_sha256: "a".repeat(64),
        cached: false,
    };
    assert!(valid.is_valid());
    let json = serde_json::to_value(&valid)?;
    assert_eq!(
        serde_json::from_value::<JudgeEvidence2>(json.clone())?,
        valid
    );
    for n in 0..6 {
        let mut changed = valid.clone();
        match n {
            0 => changed.question_ids[0] = "unknown".into(),
            1 => changed.configuration_sha256 = "x".repeat(64),
            2 => changed.thresholds.intent = 1001,
            3 => changed.scores_millionths = None,
            4 => changed.scores_millionths = Some([1_000_001, 0, 0]),
            _ => changed.configuration_sha256 = "a".into(),
        }
        assert!(!changed.is_valid());
    }
    let mut unknown = json;
    unknown["secret"] = serde_json::json!("not permitted");
    assert!(serde_json::from_value::<JudgeEvidence2>(unknown).is_err());
    let unavailable = JudgeEvidence2 {
        outcome: JudgeOutcome2::Unavailable,
        scores_millionths: None,
        ..valid
    };
    assert!(unavailable.is_valid());
    Ok(())
}
