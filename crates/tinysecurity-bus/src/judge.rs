//! Sanitized fixed-vocabulary evidence for an optional native judge.
use serde::{Deserialize, Serialize};
/// Outcome codes contain no provider response, endpoint or credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JudgeOutcome2 {
    /// Scores met every local bound.
    Qualified,
    /// At least one local threshold failed.
    Uncertain,
    /// No outbound request was allowed by the shared budget or clock.
    Budget,
    /// Total deadline elapsed.
    Timeout,
    /// Invalid IDs, primitive types or scores.
    Invalid,
    /// HTTP, authentication, transport or decoding failure.
    Unavailable,
}
/// Typed durable evidence; probability rounding never supplies permission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JudgeEvidence2 {
    /// Fixed local outcome, never provider text.
    pub outcome: JudgeOutcome2,
    /// Fixed question order: intent, reversible, exfiltrate.
    pub question_ids: [String; 3],
    /// Scores conservatively rounded to millionths (lower/lower/upper).
    pub scores_millionths: Option<[u32; 3]>,
    /// Inclusive local threshold bounds in thousandths.
    pub thresholds: crate::JudgeThresholds,
    /// Exact configuration and question-version digest.
    pub configuration_sha256: String,
    /// Whether exact-binding scores were read from cache.
    pub cached: bool,
}
impl JudgeEvidence2 {
    /// Check only bounded evidence shape; this does not confer authorization.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.question_ids == ["intent", "reversible", "exfiltrate"].map(str::to_owned)
            && self.configuration_sha256.len() == 64
            && self
                .configuration_sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
            && [
                self.thresholds.intent,
                self.thresholds.reversible,
                self.thresholds.exfiltrate,
            ]
            .iter()
            .all(|v| *v <= 1000)
            && self.scores_millionths.is_some()
                == matches!(
                    self.outcome,
                    JudgeOutcome2::Qualified | JudgeOutcome2::Uncertain
                )
            && self
                .scores_millionths
                .is_none_or(|s| s.into_iter().all(|v| v <= 1_000_000))
    }
}
#[cfg(test)]
#[path = "judge_tests.rs"]
mod tests;
