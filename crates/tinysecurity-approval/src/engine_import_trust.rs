//! Import-once receipts for host-owned legacy trust sources.
//!
//! Each source item is recorded in the same durable row that carries its grant.
//! Cancellation changes the row state but leaves the source marker in the store,
//! so a later startup retry cannot recreate revoked authority.
use super::{
    ApprovalChoice2, ApprovalLifecycle2, ApprovalRow2, ApprovalScope2, CallerContext, Engine,
    Error, EvaluateRequest, Origin, RedactMode, Result, binding, engine_flow_trust as flow_trust,
    engine_tool_trust as tool_trust,
};
use tinysecurity_bus::{
    FLOW_TRUST_LIFETIME_MS2, ImportTrustItem2, ImportTrustOutcome2, ImportTrustReceipt2,
    ImportTrustSourceRequest2, TOOL_TRUST_LIFETIME_MS2,
};

const MAX_SCOPE_ROWS: usize = 960;

fn valid_source(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn source_marker(reg: &ApprovalScope2, request: &ImportTrustSourceRequest2) -> Result<String> {
    let scope = binding::scope_handle(&reg.subject)?;
    let item = serde_json::to_vec(&request.item).map_err(|_| Error::Invalid)?;
    let mut bytes = Vec::with_capacity(scope.user.len() + scope.agent.len() + item.len() + 256);
    for value in [
        scope.tenant.as_str(),
        scope.user.as_str(),
        scope.agent.as_str(),
        request.source_id.as_str(),
        request.source_version.as_str(),
    ] {
        bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    bytes.extend_from_slice(&(item.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&item);
    Ok(binding::digest(
        b"tinysecurity/trust-source-item/v1\0",
        &bytes,
    ))
}

fn marker_exists(rows: &[ApprovalRow2], marker: &str, attribution: &str) -> Option<&ApprovalRow2> {
    rows.iter().find(|row| {
        row.attribution.as_deref() == Some(attribution)
            && row.binding.call_sha256 == marker
            && row.decision_ticket_sha256.is_none()
    })
}

impl Engine {
    /// Record one stable host source item exactly once in the approval store.
    ///
    /// The host calls once per item, allowing a partially completed source import to
    /// retry safely. Re-importing a revoked item returns its original receipt without
    /// restoring authority. Ordinary explicit grants remain independent.
    /// # Errors
    /// Rejects invalid source identifiers or trust names, unknown scopes, stale audit
    /// correlations, unavailable storage, and unacknowledged durability.
    pub async fn import_trust_source(
        &self,
        request: ImportTrustSourceRequest2,
    ) -> Result<ImportTrustReceipt2> {
        if !valid_source(&request.source_id, 128) || !valid_source(&request.source_version, 64) {
            return Err(Error::Invalid);
        }
        // The two trust kinds have separate existing locks. Taking both here makes
        // source import linearizable with either kind of grant or revocation.
        let _tool_serial = self.tool_trust_lock.lock().await;
        let _flow_serial = self.flow_trust_lock.lock().await;
        let reg = self.registration(&request.scope_id)?;
        Self::correlation(&request.audit, reg.generation)?;
        let marker = source_marker(&reg, &request)?;
        let rows = self.rows(&reg).await?;
        let (attribution, choice, tool, flow, grant_key, lifetime_ms, active_exists) =
            match &request.item {
                ImportTrustItem2::Tool { tool } => {
                    if !tool_trust::valid_tool(tool) {
                        return Err(Error::Invalid);
                    }
                    let key = tool_trust::trust_key(tool);
                    (
                        tool_trust::IMPORT_ATTRIBUTION,
                        ApprovalChoice2::Tool,
                        tool.as_str(),
                        None,
                        key,
                        TOOL_TRUST_LIFETIME_MS2,
                        Engine::durable_tool_trust(&reg, &rows, tool, self.now()?),
                    )
                }
                ImportTrustItem2::FlowTool { flow_id, tool } => {
                    if !flow_trust::trust_pair_valid(flow_id, tool) {
                        return Err(Error::Invalid);
                    }
                    let key = flow_trust::trust_key(flow_id, tool);
                    let flow_text =
                        binding::text(&self.redactor()?, flow_id, RedactMode::IdentifierHash)?;
                    let existing = Engine::durable_flow_trust(
                        &reg,
                        &rows,
                        &EvaluateRequest {
                            caller: CallerContext {
                                flow: Some(flow_text),
                                ..Default::default()
                            },
                            call: tinysecurity_bus::ToolCall {
                                tool: tool.clone(),
                                arguments_json: "{}".into(),
                                checks: Vec::new(),
                            },
                        },
                        self.now()?,
                    );
                    (
                        flow_trust::IMPORT_ATTRIBUTION,
                        ApprovalChoice2::Flow,
                        tool.as_str(),
                        Some(flow_id.as_str()),
                        key,
                        FLOW_TRUST_LIFETIME_MS2,
                        existing,
                    )
                }
            };
        if let Some(existing) = marker_exists(&rows, &marker, attribution) {
            return Ok(ImportTrustReceipt2 {
                scope_id: request.scope_id,
                outcome: ImportTrustOutcome2::AlreadyImported,
                request_id: existing.request_id.clone(),
            });
        }
        if rows.len() >= MAX_SCOPE_ROWS {
            return Err(Error::Unavailable);
        }
        let now = self.now()?;
        let redactor = self.redactor()?;
        let flow = flow
            .map(|flow_id| binding::text(&redactor, flow_id, RedactMode::IdentifierHash))
            .transpose()?;
        let caller = CallerContext {
            agent: binding::text(&redactor, &reg.subject.agent, RedactMode::IdentifierHash)?,
            thread: None,
            flow,
            call_id: binding::text(&redactor, &marker, RedactMode::IdentifierHash)?,
            origin: Origin::Operator,
            tier: reg.ceiling.clone(),
        };
        let row = ApprovalRow2 {
            request_id: binding::opaque()?,
            version: 1,
            binding: tinysecurity_bus::ApprovalBinding2 {
                binding_version: 1,
                scope: binding::scope_handle(&reg.subject)?,
                policy_ref: binding::digest(
                    b"tinysecurity/approval-policy/v1\0",
                    reg.policy_ref.as_bytes(),
                ),
                generation: reg.generation,
                call_sha256: marker,
                content_sha256: grant_key,
                origin: Origin::Operator,
                caller,
            },
            host_instance: self.instance.clone(),
            nonce: binding::opaque()?,
            tool_name: binding::text(&redactor, tool, RedactMode::Text)?,
            external_effect: true,
            args_redacted: "{}".into(),
            summary: "imported trust source item".into(),
            created_at_ms: now,
            expires_at_ms: now.checked_add(lifetime_ms).ok_or(Error::Invalid)?,
            state: if active_exists {
                ApprovalLifecycle2::Cancelled
            } else {
                ApprovalLifecycle2::Approved
            },
            choice: Some(choice),
            attribution: Some(attribution.into()),
            decision_ticket_sha256: None,
            outcome: None,
            reservation_id: None,
            legacy_history_json: None,
            judge: None,
            audit: request.audit,
        };
        self.persist(None, &row).await?;
        Ok(ImportTrustReceipt2 {
            scope_id: request.scope_id,
            outcome: ImportTrustOutcome2::Imported,
            request_id: row.request_id,
        })
    }
}
