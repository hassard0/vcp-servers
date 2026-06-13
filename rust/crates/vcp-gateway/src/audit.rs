//! Audit events (§20). Every invocation emits a signed, OpenTelemetry-compatible
//! audit event. Events MUST NOT contain secrets and SHOULD carry only hashes of
//! sensitive arguments (§19).

use serde::{Deserialize, Serialize};

use vcp_sdk::jcs;
use vcp_sdk::signer::Signer;

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
        timestamp: timestamp.to_string(),
        signature: None,
    }
    .sign(signer)
}
