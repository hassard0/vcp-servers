//! Audit events (§20). Every invocation emits a signed, OpenTelemetry-compatible
//! audit event. Events MUST NOT contain secrets and SHOULD carry only hashes of
//! sensitive arguments (§19).

use serde::{Deserialize, Serialize};

use vcp_sdk::jcs;
use vcp_sdk::signer::Signer;

use crate::delegation::DelegationChain;

/// In-band signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditSignature {
    pub alg: String,
    pub value: String,
}

/// A signed audit event (§20).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditEvent {
    pub event: String,
    pub trace_id: String,
    pub subject: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub provider: Option<String>,
    pub capability_id: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub plan_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub argument_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub grant_id: Option<String>,
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reason_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub effect: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub result_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub effect_committed: Option<bool>,
    /// The full OBO delegation chain for this call (§26.5).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub delegation_chain: Option<DelegationChain>,
    /// The audience of the exchanged upstream credential, by reference (§26.5).
    /// Never the token itself.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub credential_audience: Option<String>,
    /// The exchanged credential's key thumbprint, by reference (§26.5).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub credential_jkt: Option<String>,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub signature: Option<AuditSignature>,
}

impl AuditEvent {
    fn signing_bytes(&self) -> String {
        let mut v = serde_json::to_value(self).expect("audit event serializes");
        if let serde_json::Value::Object(ref mut map) = v {
            map.remove("signature");
        }
        jcs::canonicalize_value(&v)
    }

    /// Sign this event in place.
    pub fn sign(mut self, signer: &dyn Signer) -> Self {
        let value = signer.sign(self.signing_bytes().as_bytes());
        self.signature = Some(AuditSignature {
            alg: signer.alg().to_string(),
            value,
        });
        self
    }
}

/// Build (and sign) an `vcp.capability.invoked` audit event. `argument_hash` is
/// carried, never the raw arguments (§19).
#[allow(clippy::too_many_arguments)]
pub fn audit_event(
    event: &str,
    trace_id: &str,
    subject: &str,
    capability_id: &str,
    decision: &str,
    timestamp: &str,
    signer: &dyn Signer,
) -> AuditEvent {
    AuditEvent {
        event: event.to_string(),
        trace_id: trace_id.to_string(),
        subject: subject.to_string(),
        host: None,
        model: None,
        provider: None,
        capability_id: capability_id.to_string(),
        plan_hash: None,
        argument_hash: None,
        grant_id: None,
        decision: decision.to_string(),
        reason_code: None,
        effect: None,
        result_hash: None,
        effect_committed: None,
        delegation_chain: None,
        credential_audience: None,
        credential_jkt: None,
        timestamp: timestamp.to_string(),
        signature: None,
    }
    .sign(signer)
}

/// Inputs for a per-provider upstream audit event in a multi-provider fan-out
/// (§26.5): the call carries the full delegation chain and the exchanged
/// credential's audience/thumbprint (by reference, never the token).
pub struct UpstreamAudit<'a> {
    pub trace_id: &'a str,
    pub subject: &'a str,
    pub provider: &'a str,
    pub capability_id: &'a str,
    pub plan_hash: &'a str,
    pub argument_hash: &'a str,
    pub grant_id: &'a str,
    pub decision: &'a str,
    pub effect: &'a str,
    pub delegation_chain: DelegationChain,
    pub credential_audience: &'a str,
    pub credential_jkt: &'a str,
    pub timestamp: &'a str,
}

/// Build (and sign) an upstream-call audit event carrying the delegation chain
/// and the exchanged credential's audience (§26.5).
pub fn upstream_audit_event(u: UpstreamAudit, signer: &dyn Signer) -> AuditEvent {
    AuditEvent {
        event: "vcp.capability.invoked".to_string(),
        trace_id: u.trace_id.to_string(),
        subject: u.subject.to_string(),
        host: None,
        model: None,
        provider: Some(u.provider.to_string()),
        capability_id: u.capability_id.to_string(),
        plan_hash: Some(u.plan_hash.to_string()),
        argument_hash: Some(u.argument_hash.to_string()),
        grant_id: Some(u.grant_id.to_string()),
        decision: u.decision.to_string(),
        reason_code: None,
        effect: Some(u.effect.to_string()),
        result_hash: None,
        effect_committed: None,
        delegation_chain: Some(u.delegation_chain),
        credential_audience: Some(u.credential_audience.to_string()),
        credential_jkt: Some(u.credential_jkt.to_string()),
        timestamp: u.timestamp.to_string(),
        signature: None,
    }
    .sign(signer)
}
