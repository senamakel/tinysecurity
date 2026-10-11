//! Persistent fixture callback authority: append+fsync row and original receipt ledger.
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
};
use tinysecurity_bus::{
    ApprovalCasRequest2, ApprovalCasResponse2, ApprovalChoice2, ApprovalLoadRequest2,
    ApprovalLoadResponse2, ApprovalRecord2, ApprovalRow2, HumanDecisionReceipt2,
    VerifyHumanRequest2,
};
#[derive(Debug)]
pub(crate) struct DiskStore {
    path: PathBuf,
    pub(crate) mutations: BTreeMap<String, ApprovalCasRequest2>,
    pub(crate) tickets: BTreeMap<String, HumanDecisionReceipt2>,
}
impl DiskStore {
    pub(crate) fn open(path: &Path) -> tinybus::Result<Self> {
        let mut store = Self {
            path: path.into(),
            mutations: BTreeMap::new(),
            tickets: BTreeMap::new(),
        };
        let bytes = std::fs::read(path)
            .map_err(|_| tinybus::Error::failed("fixture journal unavailable"))?;
        if bytes.len() > 4_000_000 {
            return Err(tinybus::Error::failed("fixture journal capacity"));
        }
        for line in bytes.split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
            let event: serde_json::Value = serde_json::from_slice(line)?;
            if let Some(value) = event.get("mutation") {
                let request: ApprovalCasRequest2 = serde_json::from_value(value.clone())?;
                let receipt = Self::receipt(&request);
                request
                    .verify_receipt(&receipt)
                    .map_err(|_| tinybus::Error::failed("fixture invalid journal"))?;
                if store
                    .mutations
                    .insert(request.mutation_id.clone(), request)
                    .is_some()
                {
                    return Err(tinybus::Error::failed("fixture duplicate mutation"));
                }
            } else if let Some(value) = event.get("ticket") {
                let ticket: HumanDecisionReceipt2 = serde_json::from_value(value.clone())?;
                if store
                    .tickets
                    .insert(ticket.ticket_sha256.clone(), ticket)
                    .is_some()
                {
                    return Err(tinybus::Error::failed("fixture duplicate ticket"));
                }
            } else {
                return Err(tinybus::Error::failed("fixture invalid journal"));
            }
        }
        Ok(store)
    }
    fn append(&self, value: &serde_json::Value) -> tinybus::Result<()> {
        let mut bytes = serde_json::to_vec(value)?;
        bytes.push(b'\n');
        assert!(!String::from_utf8_lossy(&bytes).contains("private-secret"));
        let mut file = OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(|_| tinybus::Error::failed("fixture journal unavailable"))?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| tinybus::Error::failed("fixture journal unavailable"))
    }
    fn receipt(request: &ApprovalCasRequest2) -> ApprovalCasResponse2 {
        ApprovalCasResponse2 {
            scope: request.scope.clone(),
            record_id: request.record_id.clone(),
            mutation_id: request.mutation_id.clone(),
            resulting_version: request.next_record.version,
        }
    }
    pub(crate) fn load(
        &self,
        request: &ApprovalLoadRequest2,
    ) -> tinybus::Result<ApprovalLoadResponse2> {
        let mut rows = BTreeMap::<String, ApprovalRecord2>::new();
        for mutation in self.mutations.values().filter(|m| m.scope == request.scope) {
            let row = &mutation.next_record;
            if rows
                .get(&row.record_id)
                .is_none_or(|existing| existing.version < row.version)
            {
                rows.insert(row.record_id.clone(), row.clone());
            }
        }
        let response = ApprovalLoadResponse2 {
            scope: request.scope.clone(),
            records: rows.into_values().collect(),
        };
        request
            .verify_response(&response)
            .map_err(|_| tinybus::Error::failed("fixture invalid load"))?;
        Ok(response)
    }
    pub(crate) fn cas(
        &mut self,
        request: ApprovalCasRequest2,
    ) -> tinybus::Result<ApprovalCasResponse2> {
        if let Some(prior) = self.mutations.get(&request.mutation_id) {
            return if prior == &request {
                Ok(Self::receipt(prior))
            } else {
                Err(tinybus::Error::failed("fixture mutation conflict"))
            };
        }
        let current = self
            .load(&ApprovalLoadRequest2 {
                scope: request.scope.clone(),
            })?
            .records
            .into_iter()
            .find(|r| r.record_id == request.record_id);
        if current.map(|r| r.version) != request.expected_version {
            return Err(tinybus::Error::failed("fixture version conflict"));
        }
        let receipt = Self::receipt(&request);
        request
            .verify_receipt(&receipt)
            .map_err(|_| tinybus::Error::failed("fixture invalid mutation"))?;
        self.append(&serde_json::json!({"mutation":request}))?;
        self.mutations.insert(request.mutation_id.clone(), request);
        Ok(receipt)
    }
    pub(crate) fn human_action(
        &mut self,
        row: ApprovalRow2,
        choice: ApprovalChoice2,
    ) -> tinybus::Result<String> {
        // Simulated authenticated UI action. This private fixture function is never
        // exposed as a bus member and cannot be invoked through model JSON.
        let ticket = tinysecurity::audit::opaque_id()
            .map_err(|_| tinybus::Error::failed("fixture entropy"))?;
        let ticket_sha256 = format!("{:x}", Sha256::digest(ticket.as_bytes()));
        let receipt = HumanDecisionReceipt2 {
            row,
            ticket_sha256: ticket_sha256.clone(),
            actor: "authenticated-fixture-user".into(),
            choice,
        };
        self.append(&serde_json::json!({"ticket":receipt}))?;
        self.tickets.insert(ticket_sha256, receipt);
        Ok(ticket)
    }
    pub(crate) fn human(
        &self,
        request: &VerifyHumanRequest2,
    ) -> tinybus::Result<HumanDecisionReceipt2> {
        let digest = format!("{:x}", Sha256::digest(request.decision_ticket.as_bytes()));
        let receipt = self
            .tickets
            .get(&digest)
            .ok_or_else(|| tinybus::Error::failed("fixture unverified human"))?;
        if receipt.row != request.row {
            return Err(tinybus::Error::failed("fixture ticket binding mismatch"));
        }
        Ok(receipt.clone())
    }
}
