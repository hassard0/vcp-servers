//! Environment attestation verification (§27): the Gateway as RATS Verifier.
//!
//! §27.4 maps VCP onto the RATS architecture: the **Gateway is the Verifier** and
//! **policy is the Relying Party**. When a capability sets
//! `effects.requires_attestation: true` (§27.1), the Gateway gates grant minting on
//! a verified environment statement of the executing actor. When attestation is not
//! required, there is **zero** added round-trip (§27 friction constraint) and the
//! call is allowed unconditionally.
//!
//! When attestation is required the Gateway MUST (§27.4):
//!
//! 1. issue a fresh `nonce` and verify the statement is bound to it (freshness /
//!    anti-replay);
//! 2. verify `build_digest` is in the trust set (or matches manifest provenance,
//!    RFC 0002) and that the statement is unexpired;
//! 3. on failure, deny with `ATTESTATION_REQUIRED` (missing) or
//!    `ATTESTATION_INVALID` (present but bad) and **mint no grant**;
//! 4. record the result by reference in the audit event (§20).
//!
//! This module reproduces every verdict in
//! `conformance/vectors/environment-attestation.json` and provides the
//! signature-checking path used at real grant-minting call sites.

use time::OffsetDateTime;

use vcp_sdk::attestation::EnvironmentStatement;
use vcp_sdk::signer::Verifier;

use crate::grant::{parse_rfc3339, Decision};
use crate::reason::ReasonCode;

/// Appraise an environment statement for grant minting (§27.4).
///
/// - not required ⇒ allow `OK` (zero friction; statement, if any, is ignored);
/// - required + missing ⇒ deny `ATTESTATION_REQUIRED`;
/// - required + wrong nonce / untrusted build / expired ⇒ deny
///   `ATTESTATION_INVALID`;
/// - required + valid ⇒ allow `OK`.
///
/// `now` is evaluation time and `challenge_nonce` is the Gateway-issued freshness
/// nonce. This entry point performs the freshness, trust-set, and expiry checks of
/// §27.4 steps 1–2; signature verification (also part of step 2 for a wire
/// statement) is layered via [`verify_signed_environment_attestation`].
pub fn verify_environment_attestation(
    statement: Option<&EnvironmentStatement>,
    requires: bool,
    challenge_nonce: &str,
    now: OffsetDateTime,
    trusted_build_digests: &[String],
) -> (Decision, ReasonCode) {
    // Zero friction on the common path (§27.1): no attestation demanded ⇒ allow,
    // and any presented statement is irrelevant.
    if !requires {
        return (Decision::Allow, ReasonCode::Ok);
    }

    // Required but none presented ⇒ ATTESTATION_REQUIRED (§27.4 step 3).
    let stmt = match statement {
        Some(s) => s,
        None => return (Decision::Deny, ReasonCode::AttestationRequired),
    };

    // Present but bad ⇒ ATTESTATION_INVALID (§27.4 step 3). Each sub-check below is
    // a distinct invalidity the vector exercises.

    // Freshness / anti-replay: bound to the Gateway's challenge nonce (step 1).
    // Exact, byte-for-byte comparison (§3).
    if stmt.nonce != challenge_nonce {
        return (Decision::Deny, ReasonCode::AttestationInvalid);
    }

    // Trust set: the claimed build digest MUST be trusted (step 2).
    if !trusted_build_digests.iter().any(|d| d == &stmt.build_digest) {
        return (Decision::Deny, ReasonCode::AttestationInvalid);
    }

    // Unexpired: reject at or after expiry (step 2). An unparseable expiry fails
    // closed.
    match parse_rfc3339(&stmt.expires_at) {
        Some(exp) if now >= exp => return (Decision::Deny, ReasonCode::AttestationInvalid),
        None => return (Decision::Deny, ReasonCode::AttestationInvalid),
        _ => {}
    }

    (Decision::Allow, ReasonCode::Ok)
}

/// The full §27.4 step-2 verification including the statement **signature**. Used
/// at real grant-minting call sites where a wire statement carries a signature
/// over its body (a signature failure ⇒ `ATTESTATION_INVALID`). When attestation
/// is not required this short-circuits to allow exactly like
/// [`verify_environment_attestation`].
pub fn verify_signed_environment_attestation(
    statement: Option<&EnvironmentStatement>,
    requires: bool,
    challenge_nonce: &str,
    now: OffsetDateTime,
    trusted_build_digests: &[String],
    verifier: &dyn Verifier,
) -> (Decision, ReasonCode) {
    // First the freshness / trust-set / expiry / presence checks (§27.4 1–2).
    let (decision, reason) = verify_environment_attestation(
        statement,
        requires,
        challenge_nonce,
        now,
        trusted_build_digests,
    );
    if decision == Decision::Deny || !requires {
        return (decision, reason);
    }

    // Then the signature over the statement body (§3 / §27.4 step 2). `requires`
    // is true and the prior checks passed, so `statement` is Some here.
    let stmt = statement.expect("statement present when required and checks passed");
    let sig_ok = match &stmt.signature {
        Some(sig) => verifier.verify(stmt.signing_bytes().as_bytes(), &sig.value),
        None => false, // a required statement with no signature is invalid, fail closed
    };
    if sig_ok {
        (Decision::Allow, ReasonCode::Ok)
    } else {
        (Decision::Deny, ReasonCode::AttestationInvalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vcp_sdk::attestation::{AttestationClaims, Attester, StatementAttester};
    use vcp_sdk::signer::{Ed25519Signer, Ed25519Verifier};

    fn now() -> OffsetDateTime {
        parse_rfc3339("2026-06-13T16:00:00Z").unwrap()
    }

    #[test]
    fn not_required_allows_even_without_statement() {
        let (d, r) = verify_environment_attestation(None, false, "n", now(), &[]);
        assert_eq!(d, Decision::Allow);
        assert_eq!(r, ReasonCode::Ok);
    }

    #[test]
    fn signed_path_rejects_bad_signature() {
        let signer = Ed25519Signer::from_label("p");
        let other = Ed25519Signer::from_label("attacker");
        let trusted = vec!["sha256:abab".to_string()];
        let stmt = StatementAttester::new(
            AttestationClaims {
                subject_role: "provider".to_string(),
                issuer: "did:web:p".to_string(),
                build_digest: "sha256:abab".to_string(),
                container_digest: None,
                boot_epoch: 1,
            },
            &signer,
        )
        .attest("nonce-1", "2026-06-13T16:30:00Z");

        // Verified with the wrong key ⇒ ATTESTATION_INVALID.
        let wrong = Ed25519Verifier::from_signer(&other);
        let (d, r) = verify_signed_environment_attestation(
            Some(&stmt),
            true,
            "nonce-1",
            now(),
            &trusted,
            &wrong,
        );
        assert_eq!(d, Decision::Deny);
        assert_eq!(r, ReasonCode::AttestationInvalid);

        // Verified with the right key ⇒ OK.
        let right = Ed25519Verifier::from_signer(&signer);
        let (d, r) = verify_signed_environment_attestation(
            Some(&stmt),
            true,
            "nonce-1",
            now(),
            &trusted,
            &right,
        );
        assert_eq!(d, Decision::Allow);
        assert_eq!(r, ReasonCode::Ok);
    }
}
