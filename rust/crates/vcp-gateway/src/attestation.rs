//! Result attestation (§9). Every result carries a Provider-signed attestation.
//! The Gateway MUST verify the signature and that `capability_id` and
//! `argument_hash` match what it authorized, and that `result_hash` matches the
//! returned result, before releasing the (tainted) result to the Planner.
//! Verification failure discards the result (§19).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use vcp_sdk::jcs;
use vcp_sdk::signer::{Signer, Verifier};

/// In-band provider signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProviderSignature {
    pub alg: String,
    pub value: String,
}

/// The attestation body (§9).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Attestation {
    pub capability_id: String,
    pub argument_hash: String,
    pub result_hash: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub idempotency_key: Option<String>,
    pub effect_committed: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub observed_external_refs: Option<Vec<String>>,
    pub provider_signature: ProviderSignature,
}

impl Attestation {
    /// JCS bytes the provider signs: the attestation without its
    /// `provider_signature` block.
    pub fn signing_bytes(&self) -> String {
        let mut v = serde_json::to_value(self).expect("attestation serializes");
        if let Value::Object(ref mut map) = v {
            map.remove("provider_signature");
        }
        jcs::canonicalize_value(&v)
    }
}

/// Result + attestation envelope (§9).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttestedResult {
    pub result: Value,
    pub attestation: Attestation,
}

/// Build a signed attested result (provider side).
pub fn sign_result(
    capability_id: &str,
    argument_hash: &str,
    result: Value,
    effect_committed: bool,
    idempotency_key: Option<String>,
    observed_external_refs: Option<Vec<String>>,
    provider: &dyn Signer,
) -> AttestedResult {
    let result_hash = jcs::hash_value(&result);
    let mut att = Attestation {
        capability_id: capability_id.to_string(),
        argument_hash: argument_hash.to_string(),
        result_hash,
        idempotency_key,
        effect_committed,
        observed_external_refs,
        provider_signature: ProviderSignature {
            alg: provider.alg().to_string(),
            value: String::new(),
        },
    };
    let value = provider.sign(att.signing_bytes().as_bytes());
    att.provider_signature.value = value;
    AttestedResult {
        result,
        attestation: att,
    }
}

/// Why an attestation was rejected (§9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationError {
    BadSignature,
    CapabilityMismatch,
    ArgumentHashMismatch,
    ResultHashMismatch,
}

/// Verify an attested result against what the Gateway authorized (§9). On any
/// failure the result MUST be discarded.
pub fn verify_attestation(
    attested: &AttestedResult,
    expected_capability_id: &str,
    expected_argument_hash: &str,
    provider_verifier: &dyn Verifier,
) -> Result<(), AttestationError> {
    let att = &attested.attestation;

    // Signature over the attestation body.
    if !provider_verifier.verify(att.signing_bytes().as_bytes(), &att.provider_signature.value) {
        return Err(AttestationError::BadSignature);
    }
    // capability_id and argument_hash must match what was authorized (§9).
    if att.capability_id != expected_capability_id {
        return Err(AttestationError::CapabilityMismatch);
    }
    if att.argument_hash != expected_argument_hash {
        return Err(AttestationError::ArgumentHashMismatch);
    }
    // result_hash must match the actual returned result.
    if att.result_hash != jcs::hash_value(&attested.result) {
        return Err(AttestationError::ResultHashMismatch);
    }
    Ok(())
}
