//! Descriptor-level privacy decision (contract 1.22 `PrivacyCheck2`).
//!
//! Pure and in-memory: the decision depends only on the request. The adapter supplies
//! the live policy generation.
use tinysecurity_bus::{
    DenialReason, PrivacyCheckRequest2, PrivacyDataClass2, PrivacyMode, PrivacyRisk2,
    PrivacyRiskLevel2, Verdict,
};

/// Lower-cased fragments that make a risk category identifying.
const IDENTIFYING_FRAGMENTS: &[&str] = &[
    "credential",
    "secret",
    "token",
    "password",
    "identifier",
    "email",
    "phone",
    "ssn",
    "card",
];

fn identifying(category: &str) -> bool {
    let lowered = category.to_lowercase();
    IDENTIFYING_FRAGMENTS
        .iter()
        .any(|fragment| lowered.contains(fragment))
}

/// An assessed `none`/`low` risk with no identifying category.
fn assessed_safe(risk: Option<&PrivacyRisk2>) -> bool {
    risk.is_some_and(|risk| {
        matches!(risk.level, PrivacyRiskLevel2::None | PrivacyRiskLevel2::Low)
            && !risk.categories.iter().any(|category| identifying(category))
    })
}

/// Decide one transfer. Callers validate the request first.
///
/// `Standard`, a local destination and the control plane always pass. `LocalOnly`
/// refuses every external, non-control-plane transfer. `Sensitive` refuses external
/// user content unless it was assessed as `none`/`low` risk with no identifying
/// category; an unassessed payload is refused.
#[must_use]
pub fn privacy_verdict(request: &PrivacyCheckRequest2) -> Verdict {
    let deny = Verdict::Deny {
        reason: DenialReason::Privacy,
    };
    if !request.external || request.class == PrivacyDataClass2::ControlPlane {
        return Verdict::Allow;
    }
    match request.privacy {
        PrivacyMode::LocalOnly => deny,
        PrivacyMode::Sensitive
            if request.class == PrivacyDataClass2::UserContent
                && !assessed_safe(request.risk.as_ref()) =>
        {
            deny
        }
        PrivacyMode::Standard | PrivacyMode::Sensitive => Verdict::Allow,
    }
}

#[cfg(test)]
#[path = "privacy_check_tests.rs"]
mod tests;
