//! Manifest verification (§5.2 admission steps 1–2).
//!
//! Before exposing a capability the Gateway MUST verify the signature over the
//! canonicalized manifest and confirm the recomputed `contract_hash` matches
//! `capability.id`. Identifier comparison is exact, byte for byte (§3).

use vcp_sdk::identity;
use vcp_sdk::manifest::Manifest;
use vcp_sdk::signer::Verifier;

/// Why a manifest was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// Signature did not verify under the issuer's key.
    BadSignature,
    /// Recomputed `contract_hash` did not match the embedded value.
    ContractHashMismatch,
    /// `capability.id` did not equal `vcp:cap:<name>@<contract_hash>`.
    IdentityMismatch,
    /// `issuer` is not in the configured trust set.
    UntrustedIssuer,
}

/// Verify a manifest (§5.2 steps 1–3).
///
/// - `verifier` checks the issuer's signature over `JCS(manifest_without_signature)`.
/// - The `contract_hash` is recomputed from the contract partition and compared.
/// - `capability.id` must be exactly `vcp:cap:<name>@<contract_hash>`.
/// - `trusted_issuers`, when non-empty, gates admission by issuer.
pub fn verify_manifest(
    manifest: &Manifest,
    verifier: &dyn Verifier,
    trusted_issuers: &[String],
) -> Result<(), VerifyError> {
    // Step 1: signature over the canonicalized manifest minus the signature block.
    let bytes = manifest.signing_bytes();
    if !verifier.verify(bytes.as_bytes(), &manifest.signature.value) {
        return Err(VerifyError::BadSignature);
    }

    // Step 2: recompute contract_hash from the identity-defining subset.
    let recomputed = manifest.contract().contract_hash();
    if recomputed != manifest.capability.contract_hash {
        return Err(VerifyError::ContractHashMismatch);
    }

    // ...and confirm id carries that exact hash (exact byte comparison, §3).
    let expected_id = identity::capability_id(&manifest.capability.name, &recomputed);
    if expected_id != manifest.capability.id {
        return Err(VerifyError::IdentityMismatch);
    }

    // Step 3: issuer trust (when a trust set is configured).
    if !trusted_issuers.is_empty() && !trusted_issuers.iter().any(|i| i == &manifest.issuer) {
        return Err(VerifyError::UntrustedIssuer);
    }

    Ok(())
}
