//! Policy decision interface (§6) and a taint/data-flow-aware [`DefaultPolicy`].
//!
//! VCP does not mandate an engine, only the request/response shape. The Gateway
//! MUST obtain an `allow` before minting a grant. `DefaultPolicy` implements the
//! §12 rules so that authority from `untrusted_*` data and forbidden data flows
//! are denied with structured, remediable reason codes.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::taint::{self, DataFlow, TaintDecision};

/// A declared data movement in a policy request (§6).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyDataFlow {
    pub from: String,
    pub to: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub classification: Option<String>,
    /// Sink class: `"external"` or `"internal-metadata"`. Not in the wire schema
    /// (which is open); used by the Gateway to evaluate §12.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sink: Option<String>,
}

/// Whether the call's authority derives from a tainted source. Carried out of
/// band of the §6 wire shape, since authority-provenance is a Gateway-tracked
/// property (§12), not a Provider-declared one.
#[derive(Debug, Clone, Default)]
pub struct AuthorityContext {
    /// The label of the datum being used to authorize the action, if any.
    pub authorizing_label: Option<String>,
}

/// Policy decision request (§6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRequest {
    pub vcp: String,
    pub kind: String,
    pub subject: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub model: Option<String>,
    pub capability: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub arguments: Option<Value>,
    pub argument_hash: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub plan_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub data_flows: Option<Vec<PolicyDataFlow>>,
    pub effect: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub determinism: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub risk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub approval: Option<Value>,
}

/// Bounds the Gateway encodes into the minted grant (§6).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Constraints {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub max_calls: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub expires_in_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub requires_result_attestation: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub redact_outputs_for_model: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub budget: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub network: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub resource_scope: Option<Vec<String>>,
}

/// Remediation describing what would make a denied call allowable (§6).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Remediation {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub removable_data_flows: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub required_consent: Option<String>,
}

/// Policy decision response (§6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResponse {
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub constraints: Option<Constraints>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub obligations: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reason_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub remediation: Option<Remediation>,
}

impl PolicyResponse {
    pub fn is_allow(&self) -> bool {
        self.decision == "allow"
    }
}

/// The §6 decision interface. Any engine (OPA, Cedar, cani) may implement it.
pub trait PolicyAuthority {
    /// Render an allow/deny/challenge decision. `authority` carries the
    /// Gateway-tracked provenance of the call's authority (§12), which is not
    /// part of the on-wire request.
    fn decide(&self, request: &PolicyRequest, authority: &AuthorityContext) -> PolicyResponse;
}

/// A taint/data-flow-aware default policy implementing the §12 rules. Denials
/// are structured and remediable.
pub struct DefaultPolicy {
    pub default_expires_in_seconds: u64,
}

impl Default for DefaultPolicy {
    fn default() -> Self {
        Self {
            default_expires_in_seconds: 300,
        }
    }
}

impl PolicyAuthority for DefaultPolicy {
    fn decide(&self, request: &PolicyRequest, authority: &AuthorityContext) -> PolicyResponse {
        // Rule 1 (§12): authority MUST NOT flow from untrusted_* data.
        if let Some(label) = &authority.authorizing_label {
            if let TaintDecision::Deny(code) = taint::check_authority(label, true) {
                return PolicyResponse {
                    decision: "deny".to_string(),
                    constraints: None,
                    obligations: None,
                    reason_code: Some(code.to_string()),
                    remediation: Some(Remediation {
                        message: Some(
                            "Authority derives from untrusted data; obtain explicit user \
                             instruction to authorize this action."
                                .to_string(),
                        ),
                        removable_data_flows: None,
                        required_consent: Some("user_instruction".to_string()),
                    }),
                };
            }
        }

        // Rule 2 (§12): classified data MUST NOT move to an external sink.
        if let Some(flows) = &request.data_flows {
            for f in flows {
                let classification = f.classification.as_deref().unwrap_or("");
                let sink = f.sink.as_deref().unwrap_or("internal-metadata");
                let flow = DataFlow {
                    from: &f.from,
                    to: &f.to,
                    classification,
                    sink,
                };
                if let TaintDecision::Deny(code) = taint::check_data_flow(&flow) {
                    return PolicyResponse {
                        decision: "deny".to_string(),
                        constraints: None,
                        obligations: None,
                        reason_code: Some(code.to_string()),
                        remediation: Some(Remediation {
                            message: Some(format!(
                                "Flow {} -> {} ({}) to an external sink is forbidden; restrict to \
                                 internal metadata.",
                                f.from, f.to, classification
                            )),
                            removable_data_flows: Some(vec![format!("{} -> {}", f.from, f.to)]),
                            required_consent: None,
                        }),
                    };
                }
            }
        }

        // Otherwise allow, with constraints derived from the request.
        PolicyResponse {
            decision: "allow".to_string(),
            constraints: Some(Constraints {
                max_calls: Some(1),
                expires_in_seconds: Some(self.default_expires_in_seconds),
                requires_result_attestation: Some(true),
                redact_outputs_for_model: Some(false),
                budget: None,
                network: None,
                resource_scope: None,
            }),
            obligations: Some(vec!["audit".to_string()]),
            reason_code: Some("ALLOWED_WITH_CONSTRAINTS".to_string()),
            remediation: None,
        }
    }
}
