//! Grants (§7): the unit of authority. Single-use, audience-bound,
//! argument-bound, plan-bound, time-bound, scope-bound, proof-of-possession
//! bound. Minted by the Gateway only after a policy `allow`.
//!
//! `verify_grant` reproduces every case in
//! `conformance/vectors/grant-rules.json`.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use vcp_sdk::signer::{Signer, Verifier};

/// DPoP-style proof-of-possession binding (§7).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProofOfPossession {
    pub alg: String,
    pub jkt: String,
}

/// In-band Gateway signature over the grant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GatewaySignature {
    pub alg: String,
    pub value: String,
}

/// A single-use, proof-bound authorization token (§7).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Grant {
    pub kind: String,
    pub grant_id: String,
    pub subject: String,
    pub audience: String,
    pub plan_hash: String,
    pub argument_hash: String,
    pub allowed_effect: String,
    pub expires_at: String,
    pub max_calls: u64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub network: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub resource_scope: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub budget: Option<Value>,
    pub proof_of_possession: ProofOfPossession,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub attenuated_from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub gateway_signature: Option<GatewaySignature>,
}

impl Grant {
    /// JCS bytes the Gateway signs: the grant without its `gateway_signature`
    /// block (§3 rule 4).
    pub fn signing_bytes(&self) -> String {
        let mut v = serde_json::to_value(self).expect("grant serializes");
        if let Value::Object(ref mut map) = v {
            map.remove("gateway_signature");
        }
        vcp_sdk::jcs::canonicalize_value(&v)
    }

    /// Verify the Gateway signature over this grant.
    pub fn verify_signature(&self, verifier: &dyn Verifier) -> bool {
        match &self.gateway_signature {
            Some(sig) => verifier.verify(self.signing_bytes().as_bytes(), &sig.value),
            None => false,
        }
    }
}

/// Parameters the Gateway encodes into a freshly minted grant (§7). The Gateway
/// builds these from a policy `allow` decision's constraints.
pub struct MintParams {
    pub subject: String,
    /// audience = the exact `capability_id`.
    pub audience: String,
    pub plan_hash: String,
    pub argument_hash: String,
    pub allowed_effect: String,
    pub expires_at: String,
    pub max_calls: u64,
    pub network: Vec<String>,
    pub resource_scope: Vec<String>,
    pub budget: Option<Value>,
    /// Thumbprint of the holder's key (proof-of-possession binding).
    pub holder_jkt: String,
}

/// Mint a signed grant (§7). Authority is created here and only here, after a
/// policy `allow`. The grant is bound to audience + argument_hash + plan_hash +
/// expires_at + max_calls + proof_of_possession.
pub fn mint_grant(grant_id: &str, params: MintParams, gateway_signer: &dyn Signer) -> Grant {
    let mut grant = Grant {
        kind: "vcp.capability.grant".to_string(),
        grant_id: grant_id.to_string(),
        subject: params.subject,
        audience: params.audience,
        plan_hash: params.plan_hash,
        argument_hash: params.argument_hash,
        allowed_effect: params.allowed_effect,
        expires_at: params.expires_at,
        max_calls: params.max_calls,
        network: Some(params.network),
        resource_scope: Some(params.resource_scope),
        budget: params.budget,
        proof_of_possession: ProofOfPossession {
            alg: gateway_signer.alg().to_string(),
            jkt: params.holder_jkt,
        },
        attenuated_from: None,
        gateway_signature: None,
    };
    let value = gateway_signer.sign(grant.signing_bytes().as_bytes());
    grant.gateway_signature = Some(GatewaySignature {
        alg: gateway_signer.alg().to_string(),
        value,
    });
    grant
}

/// A capability-invocation attempt to validate against a grant.
pub struct Attempt {
    /// The capability the holder is trying to call (an exact `capability_id`).
    pub capability: String,
    /// The recomputed `argument_hash` for the attempt's arguments.
    pub argument_hash: String,
}

/// Allow/deny verdict (§6/§7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

/// Verify a grant against an attempt at logical time `now`, where `call_index`
/// is the zero-based prior-use counter (0 = first use). Reproduces every
/// `grant-rules.json` verdict.
///
/// Check order is significant and fail-closed: audience, then argument binding,
/// then replay budget, then expiry. (The vectors exercise exactly one violation
/// each; this order is the one the spec narrative implies — identity before
/// budget before time.)
pub fn verify_grant(
    grant: &Grant,
    attempt: &Attempt,
    now: OffsetDateTime,
    call_index: u64,
) -> (Decision, &'static str) {
    // Audience-bound (§7): exact capability_id match, byte for byte (§3).
    if attempt.capability != grant.audience {
        return (Decision::Deny, "AUDIENCE_MISMATCH");
    }

    // Argument-bound (§7/§8): the argument hash must match exactly.
    if attempt.argument_hash != grant.argument_hash {
        return (Decision::Deny, "ARGUMENT_HASH_MISMATCH");
    }

    // Single-use / max_calls (§7): call_index is the count of prior uses.
    if call_index >= grant.max_calls {
        return (Decision::Deny, "MAX_CALLS_EXCEEDED");
    }

    // Time-bound (§7): reject at or after expiry.
    match parse_rfc3339(&grant.expires_at) {
        Some(exp) if now >= exp => return (Decision::Deny, "GRANT_EXPIRED"),
        None => return (Decision::Deny, "GRANT_EXPIRED"), // unparseable ⇒ fail closed
        _ => {}
    }

    (Decision::Allow, "OK")
}

/// Parse an RFC 3339 / ISO 8601 timestamp into an `OffsetDateTime`.
pub fn parse_rfc3339(s: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()
}
