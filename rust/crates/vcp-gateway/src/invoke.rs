//! Invocation (§8) and the end-to-end Gateway flow tying together manifest
//! verification, policy, grant minting, provider execution, and attestation.

use serde_json::Value;
use time::OffsetDateTime;

use vcp_sdk::identity;
use vcp_sdk::manifest::Manifest;
use vcp_sdk::signer::Verifier;

use crate::attestation::{self, AttestedResult};
use crate::grant::{self, Attempt, Decision, Grant};

/// A capability provider that executes within the bounds of a grant (§8).
pub trait Provider {
    /// Execute the capability and return a signed attested result. The provider
    /// MUST recompute `argument_hash` and confirm it matches the grant before
    /// committing (§8 step 2); this is enforced again Gateway-side in [`invoke`].
    fn invoke(
        &self,
        capability_id: &str,
        arguments: &Value,
        grant: &Grant,
        dry_run: bool,
    ) -> AttestedResult;
}

/// Outcome of a Gateway invocation.
#[derive(Debug, Clone, PartialEq)]
pub enum InvokeError {
    GrantDenied(&'static str),
    AttestationRejected(crate::attestation::AttestationError),
}

/// Drive one invocation end to end (§8/§9): verify the grant against the
/// attempt, call the provider, then verify the returned attestation before
/// releasing the result. Fails closed on any check.
pub fn invoke(
    provider: &dyn Provider,
    grant: &Grant,
    capability_id: &str,
    arguments: &Value,
    now: OffsetDateTime,
    call_index: u64,
    dry_run: bool,
    provider_verifier: &dyn Verifier,
) -> Result<AttestedResult, InvokeError> {
    let argument_hash = identity::argument_hash_value(arguments);
    let attempt = Attempt {
        capability: capability_id.to_string(),
        argument_hash: argument_hash.clone(),
    };

    // Grant must authorize exactly this attempt (§7/§8).
    let (decision, reason) = grant::verify_grant(grant, &attempt, now, call_index);
    if decision != Decision::Allow {
        return Err(InvokeError::GrantDenied(reason));
    }

    // Execute.
    let attested = provider.invoke(capability_id, arguments, grant, dry_run);

    // Verify the attestation before releasing the result (§9, §19).
    attestation::verify_attestation(&attested, capability_id, &argument_hash, provider_verifier)
        .map_err(InvokeError::AttestationRejected)?;

    Ok(attested)
}

/// Confirm a manifest's identity is internally consistent (helper used by the
/// end-to-end test to assert a verified manifest before invocation).
pub fn manifest_identity_ok(manifest: &Manifest) -> bool {
    let recomputed = manifest.contract().contract_hash();
    recomputed == manifest.capability.contract_hash
        && identity::capability_id(&manifest.capability.name, &recomputed) == manifest.capability.id
}
