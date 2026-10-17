use super::*;

#[test]
fn tiers_follow_the_published_thresholds() {
    assert_eq!(PromptTier2::from_score_milli(0), PromptTier2::Allow);
    assert_eq!(PromptTier2::from_score_milli(549), PromptTier2::Allow);
    assert_eq!(PromptTier2::from_score_milli(550), PromptTier2::Review);
    assert_eq!(PromptTier2::from_score_milli(699), PromptTier2::Review);
    assert_eq!(PromptTier2::from_score_milli(700), PromptTier2::Block);
    assert_eq!(
        PromptTier2::from_score_milli(PROMPT_MAX_SCORE_MILLI2),
        PromptTier2::Block
    );
}

#[test]
fn request_debug_hides_the_prompt() {
    let text = format!(
        "{:?}",
        ScanPromptScoredRequest2 {
            text: "private-prompt".into()
        }
    );
    assert!(!text.contains("private-prompt"));
}
