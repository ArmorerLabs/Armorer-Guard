use std::path::PathBuf;

use serde::Serialize;

use super::atomic_store;
use super::contracts::{ContentEffect, ContentEvaluationRequest};

#[derive(Debug, Serialize)]
pub struct ProvenanceRecord<'a> {
    pub schema_version: &'static str,
    pub trace_id: &'a str,
    pub session_id: &'a str,
    pub stage: &'a str,
    pub subject_agent_id: &'a str,
    pub subject_tenant_id: &'a str,
    pub content_ref: &'a str,
    pub origin: &'a str,
    pub principal_id: &'a str,
    pub trust: super::contracts::TrustClass,
    pub data_classes: &'a [String],
    pub instruction_authority: super::contracts::InstructionAuthority,
    pub retention: &'a str,
    pub influence_edges: &'a [String],
    pub effect: ContentEffect,
    pub observed_at: u64,
}

pub struct ProvenanceStore {
    path: PathBuf,
}

impl ProvenanceStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn record(
        &self,
        request: &ContentEvaluationRequest,
        stage: &str,
        effect: ContentEffect,
        observed_at: u64,
    ) -> Result<(), String> {
        for segment in &request.segments {
            let record = ProvenanceRecord {
                schema_version: "armorer-guard-provenance/v1",
                trace_id: &request.trace_id,
                session_id: &request.session_id,
                stage,
                subject_agent_id: &request.subject.agent_id,
                subject_tenant_id: &request.subject.tenant_id,
                content_ref: &segment.content_ref,
                origin: &segment.origin,
                principal_id: &segment.principal_id,
                trust: segment.trust,
                data_classes: &segment.data_classes,
                instruction_authority: segment.instruction_authority,
                retention: &segment.retention,
                influence_edges: &segment.influenced_by,
                effect,
                observed_at,
            };
            atomic_store::append_json(&self.path, &record)?;
        }
        Ok(())
    }
}
