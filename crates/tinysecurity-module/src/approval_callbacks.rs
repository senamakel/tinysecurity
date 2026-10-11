//! Bounded exact approval callback clients, fixed to the trusted unique init peer.
use crate::callbacks::{AuditClient, PeerBinding};
use std::sync::Arc;
use tinysecurity::approval::{Error, Ports, Result};
use tinysecurity_bus::{
    ApprovalCasRequest2, ApprovalCasResponse2, ApprovalConfig2, ApprovalDeliveryRequest2,
    ApprovalDeliveryResponse2, ApprovalLifecycle2, ApprovalLoadRequest2, ApprovalLoadResponse2,
    ApprovalRow2, AuditConfig2, AuditEvent2, AuditKind2, AuditSinkRequest2, HumanDecisionReceipt2,
    SubjectScope, VerifyHumanRequest2, callback_names2,
};
/// Captured registered callback identity; no model-provided destination or scope.
pub(crate) struct ApprovalStoreClient {
    connection: tinybus::Connection,
    peer: tinybus::BusName,
    timeout_ms: u32,
    scopes: Vec<SubjectScope>,
}
impl std::fmt::Debug for ApprovalStoreClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApprovalStoreClient([REDACTED])")
    }
}
impl ApprovalStoreClient {
    pub(crate) fn new(
        connection: tinybus::Connection,
        peer: Option<&str>,
        config: &ApprovalConfig2,
    ) -> tinybus::Result<Self> {
        let peer = peer
            .ok_or_else(|| tinybus::Error::failed("approval authority unavailable"))?
            .parse::<tinybus::BusName>()?;
        if !peer.is_unique() || !(1..=30000).contains(&config.timeout_ms) {
            return Err(tinybus::Error::failed("invalid approval initialization"));
        }
        let scopes = config
            .scopes
            .iter()
            .map(|s| tinysecurity::approval::scope_handle(&s.subject))
            .collect::<Result<Vec<_>>>()
            .map_err(|_| tinybus::Error::failed("invalid approval scope"))?;
        if scopes.is_empty() || scopes.len() > 128 {
            return Err(tinybus::Error::failed("invalid approval scope"));
        }
        Ok(Self {
            connection,
            peer,
            timeout_ms: config.timeout_ms,
            scopes,
        })
    }
    fn scope(&self, scope: &SubjectScope) -> Result<()> {
        if self.scopes.contains(scope) {
            Ok(())
        } else {
            Err(Error::Denied)
        }
    }
    fn proxy(&self, interface: &str) -> Result<tinybus::Proxy> {
        self.connection
            .proxy(self.peer.as_str(), callback_names2::OBJECT_PATH, interface)
            .map(|p| p.with_timeout(std::time::Duration::from_millis(u64::from(self.timeout_ms))))
            .map_err(|_| Error::Unavailable)
    }
    pub(crate) async fn load(
        &self,
        request: ApprovalLoadRequest2,
    ) -> Result<ApprovalLoadResponse2> {
        self.scope(&request.scope)?;
        let response = self
            .proxy(callback_names2::APPROVAL_STORE)?
            .call(callback_names2::LOAD, (request.clone(),))
            .await
            .map_err(|_| Error::Unavailable)?;
        request
            .verify_response(&response)
            .map_err(|_| Error::Invalid)?;
        Ok(response)
    }
    pub(crate) async fn cas(&self, request: ApprovalCasRequest2) -> Result<ApprovalCasResponse2> {
        self.scope(&request.scope)?;
        let response = self
            .proxy(callback_names2::APPROVAL_STORE)?
            .call(callback_names2::CAS, (request.clone(),))
            .await
            .map_err(|_| Error::Unavailable)?;
        request
            .verify_receipt(&response)
            .map_err(|_| Error::Invalid)?;
        Ok(response)
    }
}
/// Real authenticated store, delivery, human-ticket verification and audit ports.
pub(crate) struct ApprovalClients {
    store: ApprovalStoreClient,
    audit: Vec<(SubjectScope, Arc<AuditClient>)>,
}
impl std::fmt::Debug for ApprovalClients {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApprovalClients([REDACTED])")
    }
}
impl ApprovalClients {
    pub(crate) fn new(
        connection: &tinybus::Connection,
        peer: Option<&str>,
        config: &ApprovalConfig2,
        audit: &AuditConfig2,
        redactor: &tinysecurity::Redactor,
    ) -> tinybus::Result<Self> {
        let store = ApprovalStoreClient::new(connection.clone(), peer, config)?;
        let binding = PeerBinding::new(peer)?;
        let mut clients = Vec::new();
        for registration in &config.scopes {
            let scope = tinysecurity::approval::scope_handle(&registration.subject)
                .map_err(|_| tinybus::Error::failed("invalid approval scope"))?;
            let mut scoped = audit.clone();
            scoped.scope = registration.subject.clone();
            // Host reserves audit sequencing per registered subject; the base audit
            // stream remains explicit and the sink validates exact scope and stream.
            let client = AuditClient::new(
                connection.clone(),
                binding.clone(),
                scoped,
                redactor.clone(),
            )?;
            clients.push((scope, Arc::new(client)));
        }
        Ok(Self {
            store,
            audit: clients,
        })
    }
}
#[async_trait::async_trait]
impl Ports for ApprovalClients {
    async fn load(&self, request: ApprovalLoadRequest2) -> Result<ApprovalLoadResponse2> {
        self.store.load(request).await
    }
    async fn cas(&self, request: ApprovalCasRequest2) -> Result<ApprovalCasResponse2> {
        self.store.cas(request).await
    }
    async fn prompt(&self, request: ApprovalDeliveryRequest2) -> Result<ApprovalDeliveryResponse2> {
        self.store.scope(&request.row.binding.scope)?;
        let response: ApprovalDeliveryResponse2 = self
            .store
            .proxy(callback_names2::APPROVAL_PROMPT)?
            .call(callback_names2::PROMPT, (request.clone(),))
            .await
            .map_err(|_| Error::Unavailable)?;
        if response.request_id != request.row.request_id
            || response.nonce != request.row.nonce
            || !response.delivered
        {
            return Err(Error::Denied);
        }
        Ok(response)
    }
    async fn human(&self, request: VerifyHumanRequest2) -> Result<HumanDecisionReceipt2> {
        self.store.scope(&request.row.binding.scope)?;
        let response: HumanDecisionReceipt2 = self
            .store
            .proxy(callback_names2::APPROVAL_PROMPT)?
            .call(callback_names2::VERIFY_HUMAN, (request.clone(),))
            .await
            .map_err(|_| Error::Unavailable)?;
        if response.row != request.row {
            return Err(Error::Denied);
        }
        Ok(response)
    }
    async fn audit(&self, row: ApprovalRow2) -> Result<()> {
        let (_, client) = self
            .audit
            .iter()
            .find(|(s, _)| s == &row.binding.scope)
            .ok_or(Error::Denied)?;
        let batch = AuditSinkRequest2 {
            scope: client.scope().clone(),
            stream_id: client.stream_id().into(),
            expected_tail: row.audit.expected_tail,
            events: vec![AuditEvent2 {
                sequence: row
                    .audit
                    .expected_tail
                    .checked_add(1)
                    .ok_or(Error::Invalid)?,
                event_id: row.audit.event_id.clone(),
                generation: row.binding.generation,
                kind: if row.state == ApprovalLifecycle2::Executed {
                    AuditKind2::Execution
                } else {
                    AuditKind2::Approval
                },
                attribution: row.attribution.clone().unwrap_or_else(|| "pending".into()),
                arguments_json: serde_json::to_string(&row).map_err(|_| Error::Invalid)?,
                rule_ids: vec![],
            }],
        };
        let response = client.append(batch).await;
        if !response.committed || !response.permitted {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
}
#[cfg(test)]
#[path = "approval_callbacks_tests.rs"]
mod tests;
