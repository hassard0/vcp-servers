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

use crate::delegation::{DelegationChain, TokenExchange};

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

/// A small by-reference handle to a verified environment attestation (§27.2):
/// attest-once / reference-many. Per-call envelopes (and the grant) carry only
/// this ref — an id plus the nonce it was bound to — never the full evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttestationRef {
    /// Identifies the cached verified statement (e.g. issuer + boot_epoch).
    pub id: String,
    /// The Gateway challenge nonce the statement was bound to (§27.2).
    pub nonce: String,
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
    /// The ordered on-behalf-of delegation chain (§26.2). Recorded on every grant
    /// in a multi-provider fan-out.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub delegation_chain: Option<DelegationChain>,
    /// The per-provider token-exchange binding (§26.1): audience, actor claim, and
    /// the exchanged-credential thumbprint (by reference, never the token).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub token_exchange: Option<TokenExchange>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub attenuated_from: Option<String>,
    /// The verified environment-attestation reference (§27.2), present only when
    /// the capability's `effects.requires_attestation` gated this grant. Absent on
    /// the common (no-attestation) path so existing grants are unchanged.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub attestation_ref: Option<AttestationRef>,
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
    /// The OBO delegation chain to record on the grant (§26.2), if any.
    pub delegation_chain: Option<DelegationChain>,
    /// The per-provider token-exchange binding to record (§26.1), if any.
    pub token_exchange: Option<TokenExchange>,
    /// The verified environment-attestation reference to attach (§27.2), if this
    /// grant was gated on attestation.
    pub attestation_ref: Option<AttestationRef>,
}

impl Default for MintParams {
    fn default() -> Self {
        Self {
            subject: String::new(),
            audience: String::new(),
            plan_hash: String::new(),
            argument_hash: String::new(),
            allowed_effect: String::new(),
            expires_at: String::new(),
            max_calls: 1,
            network: Vec::new(),
            resource_scope: Vec::new(),
            budget: None,
            holder_jkt: String::new(),
            delegation_chain: None,
            token_exchange: None,
            attestation_ref: None,
        }
    }
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
        delegation_chain: params.delegation_chain,
        token_exchange: params.token_exchange,
        attenuated_from: None,
        attestation_ref: params.attestation_ref,
        gateway_signature: None,
    };
    let value = gateway_signer.sign(grant.signing_bytes().as_bytes());
    grant.gateway_signature = Some(GatewaySignature {
        alg: gateway_signer.alg().to_string(),
        value,
    });
    grant
}

/// Mint a grant **only if** the environment-attestation gate passes (§27.4).
///
/// `requires` mirrors the capability's `effects.requires_attestation`. When it is
/// false (the common, zero-friction path) the grant is minted unchanged — no
/// `attestation_ref` is attached and the statement is ignored. When it is true the
/// statement is appraised (freshness nonce, trusted build, expiry, signature, §27.4):
/// on failure **no grant is minted** and the `(Decision::Deny, reason)` carries
/// `ATTESTATION_REQUIRED` (missing) or `ATTESTATION_INVALID` (bad); on success the
/// grant is minted with `attestation_ref` attached (§27.2) and `(Allow, OK)`.
///
/// Returns the verdict and, on allow, the minted [`Grant`]. Fail-closed: any deny
/// yields `None`.
#[allow(clippy::too_many_arguments)]
pub fn mint_grant_gated(
    grant_id: &str,
    mut params: MintParams,
    gateway_signer: &dyn Signer,
    statement: Option<&vcp_sdk::attestation::EnvironmentStatement>,
    requires: bool,
    challenge_nonce: &str,
    now: OffsetDateTime,
    trusted_build_digests: &[String],
    statement_verifier: &dyn Verifier,
) -> (Decision, &'static str, Option<Grant>) {
    let (decision, reason) = crate::env_attestation::verify_signed_environment_attestation(
        statement,
        requires,
        challenge_nonce,
        now,
        trusted_build_digests,
        statement_verifier,
    );

    if decision == Decision::Deny {
        // §27.4 step 3 / §19: grant minting fails closed — no grant.
        return (decision, reason.as_str(), None);
    }

    // On success, attach the attestation reference by value (§27.2) only when the
    // capability actually required attestation; the common path stays unchanged.
    if requires {
        if let Some(stmt) = statement {
            params.attestation_ref = Some(AttestationRef {
                id: format!("{}#{}", stmt.issuer, stmt.boot_epoch),
                nonce: stmt.nonce.clone(),
            });
        }
    }

    let grant = mint_grant(grant_id, params, gateway_signer);
    (Decision::Allow, reason.as_str(), Some(grant))
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
