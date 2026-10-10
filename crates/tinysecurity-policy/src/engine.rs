//! Atomic policy activation and ordered evaluation.
use crate::{
    AccessTier, CONTRACT_VERSION, CallerContext, Check, CheckRequest, CheckResponse, Decision,
    DenialReason, Error, EvaluateRequest, ModuleConfig, Origin, PolicyInfo, Result, Verdict,
    command, names, path,
};
/// Active validated policy instance. Failed reconfiguration never changes it.
#[derive(Clone, Debug)]
pub struct Policy {
    config: ModuleConfig,
    generation: u64,
    redactor: tinysecurity_redact::Redactor,
}
impl Policy {
    /// Validate and activate the first policy generation.
    /// # Errors
    /// Rejects incompatible wire versions, unsupported judges and invalid roots.
    pub fn new(config: ModuleConfig) -> Result<Self> {
        validate(&config)?;
        Ok(Self {
            redactor: tinysecurity_redact::Redactor::new(&config.redactor)?,
            config,
            generation: 1,
        })
    }
    /// Activate a new generation after validating all settings.
    /// # Errors
    /// Rejects invalid settings or generation overflow without changing old state.
    pub fn reinitialize(&mut self, config: ModuleConfig) -> Result<()> {
        validate(&config)?;
        let generation = self.generation.checked_add(1).ok_or(Error::InvalidConfig)?;
        let redactor = tinysecurity_redact::Redactor::new(&config.redactor)?;
        self.config = config;
        self.redactor = redactor;
        self.generation = generation;
        Ok(())
    }
    /// Inspect effective public configuration, without init-only credentials.
    #[must_use]
    pub fn info(&self) -> PolicyInfo {
        PolicyInfo {
            contract_version: CONTRACT_VERSION,
            generation: self.generation,
            policy: self.config.policy.clone(),
            capabilities: names::METHODS.iter().map(|s| (*s).into()).collect(),
        }
    }
    /// Clone the active immutable registry without exposing initialization secrets.
    #[must_use]
    pub fn redactor(&self) -> tinysecurity_redact::Redactor {
        self.redactor.clone()
    }
    /// Authorize a supported host-owned tool and its complete concrete checks.
    /// # Errors
    /// Reserved for module failures; ordinary denial is a successful result.
    pub fn evaluate(&self, request: &EvaluateRequest) -> Result<Decision> {
        let matching = !request.call.checks.is_empty()
            && match request.call.tool.as_str() {
                "local_diagnostic" => request
                    .call
                    .checks
                    .iter()
                    .all(|c| matches!(c, Check::LocalDiagnostic {})),
                "path_check" => request
                    .call
                    .checks
                    .iter()
                    .all(|c| matches!(c, Check::Path { .. })),
                "command_check" => request
                    .call
                    .checks
                    .iter()
                    .all(|c| matches!(c, Check::Command { .. })),
                _ => false,
            };
        if !matching {
            return Ok(self.denied(DenialReason::UnsupportedEffect));
        }
        let scan = self
            .redactor
            .scan_tool_definition(&crate::ScanToolDefinitionRequest {
                name: request.call.tool.clone(),
                definition_json: request.call.arguments_json.clone(),
            })?;
        if let Some(reason) = scan_denial(&scan.verdict) {
            return Ok(self.denied(reason));
        }
        for check in &request.call.checks {
            let decision = self.one(&request.caller, check);
            if decision.verdict != Verdict::Allow {
                return Ok(decision);
            }
        }
        Ok(self.allowed())
    }
    /// Evaluate an ordered batch against a single active generation.
    /// # Errors
    /// Reserved for module failures; individual denials remain ordered results.
    pub fn check(&self, request: &CheckRequest) -> Result<CheckResponse> {
        Ok(CheckResponse {
            generation: self.generation,
            decisions: request
                .checks
                .iter()
                .map(|check| self.one(&request.caller, check))
                .collect(),
        })
    }
    fn one(&self, caller: &CallerContext, check: &Check) -> Decision {
        if caller.agent.is_empty() || caller.call_id.is_empty() {
            return self.denied(DenialReason::InvalidContext);
        }
        let result = match check {
            Check::LocalDiagnostic {} => Ok(()),
            Check::Unknown { .. } => Err(DenialReason::UnsupportedEffect),
            Check::Path { path, write } => {
                path::check(&self.config.policy, path, *write).and_then(|()| {
                    if *write && caller.tier == AccessTier::Read {
                        Err(DenialReason::Access)
                    } else if *write
                        && (caller.origin == Origin::Cron || self.config.policy.enabled)
                    {
                        Err(DenialReason::ApprovalUnavailable)
                    } else {
                        Ok(())
                    }
                })
            }
            Check::Command { command } => self
                .redactor
                .scan_prompt(&crate::ScanPromptRequest {
                    text: command.clone(),
                })
                .map_err(|_| DenialReason::Content)
                .and_then(|scan| match scan_denial(&scan.verdict) {
                    Some(reason) => Err(reason),
                    None => command::check(&self.config.policy, command),
                }),
        };
        match result {
            Ok(()) => self.allowed(),
            Err(reason) => self.denied(reason),
        }
    }
    fn allowed(&self) -> Decision {
        Decision {
            generation: self.generation,
            verdict: Verdict::Allow,
            cacheable: false,
        }
    }
    fn denied(&self, reason: DenialReason) -> Decision {
        Decision {
            generation: self.generation,
            verdict: Verdict::Deny { reason },
            cacheable: false,
        }
    }
}
fn validate(config: &ModuleConfig) -> Result<()> {
    if config.contract_version.0 != CONTRACT_VERSION.0
        || config.contract_version.1 > CONTRACT_VERSION.1
    {
        return Err(Error::IncompatibleVersion);
    }
    // No approval or judge engine is advertised. Do not accept inert credentials.
    if let Some(judge) = &config.judge {
        if judge.threshold_millis > 1000
            || judge.timeout_ms == 0
            || judge.timeout_ms > 600_000
            || judge.credential.0.is_empty()
        {
            return Err(Error::InvalidConfig);
        }
        return Err(Error::Unavailable);
    }
    let p = &config.policy;
    if p.enabled && (!path::valid_root(&p.action_dir) || !path::valid_root(&p.workspace_dir)) {
        return Err(Error::InvalidConfig);
    }
    if p.forbidden_paths
        .iter()
        .any(|root| !std::path::Path::new(root).is_absolute() || path::floor(root))
        || p.allowed_commands
            .iter()
            .any(|c| c.is_empty() || c.chars().any(char::is_whitespace))
    {
        return Err(Error::InvalidConfig);
    }
    Ok(())
}

fn scan_denial(verdict: &crate::ScanVerdict) -> Option<DenialReason> {
    match verdict {
        crate::ScanVerdict::Clean => None,
        crate::ScanVerdict::Suspicious => Some(DenialReason::ApprovalUnavailable),
        crate::ScanVerdict::Blocked => Some(DenialReason::Content),
    }
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;
