//! Descriptor-level privacy decision for call sites with no destination to pin
//! (contract 1.22).
//!
//! `ScopedEgressCheck` judges an HTTP request against a registered egress policy: a
//! URL, headers, a payload and a pinned address. Inference, embedding, connector,
//! integration, media and search call sites reach their destination through their own
//! transport and register no such policy. `PrivacyCheck2` is the privacy half alone:
//! the host's registered mode, whether the transfer leaves the device, what class of
//! data it carries and an optional identification-risk assessment.
use crate::{Decision, PrivacyMode};
use serde::{Deserialize, Serialize};

/// Longest destination label, in bytes.
pub const MAX_PRIVACY_LABEL_BYTES: usize = 256;
/// Most risk categories one assessment may carry.
pub const MAX_PRIVACY_CATEGORIES: usize = 32;
/// Longest risk category, in bytes.
pub const MAX_PRIVACY_CATEGORY_BYTES: usize = 64;

/// What a transfer carries, coarsely.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PrivacyDataClass2 {
    /// Session, auth, team, billing and connection-management round trips that carry
    /// no user content. Never refused by a privacy mode.
    ControlPlane,
    /// Ids, counts and routing fields. Refused only by `local_only`.
    Metadata,
    /// Prompts, tool arguments, embeddings input or file content.
    UserContent,
}
/// Assessed identification risk, least to most identifying. Absence of an assessment
/// is a distinct state: `Sensitive` refuses it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PrivacyRiskLevel2 {
    /// Assessed: nothing identifying.
    None,
    /// Assessed: low risk.
    Low,
    /// Assessed: medium risk.
    Medium,
    /// Assessed: high risk.
    High,
}
/// An identification-risk assessment of the payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivacyRisk2 {
    /// Assessed level.
    pub level: PrivacyRiskLevel2,
    /// Matched category names such as `email` or `credential`. The module decides
    /// which categories are identifying.
    pub categories: Vec<String>,
}

/// One privacy question about one transfer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivacyCheckRequest2 {
    /// The host's registered privacy mode. Invocation data never sets authority; the
    /// trusted host derives this from its configuration.
    pub privacy: PrivacyMode,
    /// Whether the transfer leaves the device. A local runtime is never refused.
    pub external: bool,
    /// What the transfer carries.
    pub class: PrivacyDataClass2,
    /// Coarse destination slug for diagnostics, never a payload or a full URL.
    pub destination_label: String,
    /// The payload's assessment; `None` means it was not assessed.
    pub risk: Option<PrivacyRisk2>,
}
impl PrivacyCheckRequest2 {
    /// Validate bounds before the decision runs.
    ///
    /// # Errors
    /// Rejects an oversized or control-character label and an oversized assessment.
    pub fn validate(&self) -> crate::Result<()> {
        let category_ok = |category: &String| {
            !category.is_empty()
                && category.len() <= MAX_PRIVACY_CATEGORY_BYTES
                && !category.chars().any(char::is_control)
        };
        if self.destination_label.len() > MAX_PRIVACY_LABEL_BYTES
            || self.destination_label.chars().any(char::is_control)
            || self.risk.as_ref().is_some_and(|risk| {
                risk.categories.len() > MAX_PRIVACY_CATEGORIES
                    || !risk.categories.iter().all(category_ok)
            })
        {
            return Err(crate::Error::InvalidArguments);
        }
        Ok(())
    }
}
/// The privacy decision. A refusal is `DenialReason::Privacy`; the host chooses the
/// message from the mode it asked under. Never cacheable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivacyCheckResponse2 {
    /// Permission outcome.
    pub decision: Decision,
}

#[cfg(test)]
#[path = "privacy_check_tests.rs"]
mod tests;
