//! Environment attestation (§27): the *statement* tier.
//!
//! Two different things are called "attestation" in VCP (§27). This module covers
//! **environment attestation** — attesting *what an actor is*: that a Gateway,
//! Provider, or Agent is running the genuine, unmodified code it claims, in the
//! environment it claims. (The distinct *result* attestation of §9 — attesting
//! *what a call did* — lives in `vcp-gateway`.)
//!
//! Friction is the design constraint (§27): environment attestation is **off by
//! default**, **attest-once / reference-many**, and **layered**. This module
//! implements only the **`statement`** tier (§27.3): a signed Environment
//! Statement that needs only the Ed25519 key the actor already has, proves key
//! continuity and the claimed build, and suffices for L2/L3. The `tee` tier (L4)
//! is out of scope here.
//!
//! An [`Attester`] produces a signed [`EnvironmentStatement`]; the Gateway (the
//! RATS Verifier, §27.4) appraises it. Verification lives in
//! `vcp-gateway::env_attestation` so the Planner/SDK never holds authority.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::jcs;
use crate::signer::Signer;

/// In-band signature over an [`EnvironmentStatement`] (§3 default alg Ed25519).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StatementSignature {
    pub alg: String,
    pub value: String,
}

/// A signed Environment Statement (§27.3, `statement` tier).
///
/// It attests that the actor identified by `issuer` (a `gateway`, `provider`, or
/// `agent` per `subject_role`) is running the claimed `build_digest` (and optional
/// `container_digest`), is bound to the Gateway's freshness `nonce`, and is valid
/// until `expires_at`. `boot_epoch` keys the Gateway's attest-once cache (§27.2).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EnvironmentStatement {
    /// Always `"vcp.environment.attestation"`.
    pub kind: String,
    /// Always `"statement"` for this tier (§27.3).
    pub tier: String,
    /// The attestable role: `gateway`, `provider`, or `agent` (§27.3).
    pub subject_role: String,
    /// The actor's identity (its signing key's owner), e.g. a `did:web:` issuer.
    pub issuer: String,
    /// The claimed build digest (`sha256:`); checked against the trust set or the
    /// manifest provenance (§27.4).
    pub build_digest: String,
    /// The optional container image digest (`sha256:`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub container_digest: Option<String>,
    /// Keys the Gateway's verified-result cache (§27.2): an attest-once boot/session
    /// epoch.
    pub boot_epoch: u64,
    /// The Gateway-issued freshness nonce the statement is bound to (§27.4 rule 1).
    pub nonce: String,
    /// RFC 3339 expiry; an expired statement MUST be rejected (§27.4 rule 2).
    pub expires_at: String,
    /// In-band signature over the statement without its `signature` block (§3).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub signature: Option<StatementSignature>,
}

impl EnvironmentStatement {
    /// The JCS bytes the actor signs: the statement without its `signature`
    /// block (§3 rule 4).
    pub fn signing_bytes(&self) -> String {
        let mut v = serde_json::to_value(self).expect("statement serializes");
        if let Value::Object(ref mut map) = v {
            map.remove("signature");
        }
        jcs::canonicalize_value(&v)
    }
}

/// What an [`Attester`] needs to know about its environment to produce a statement.
/// The nonce and expiry come from the Gateway's challenge; the rest is the actor's
/// own claimed identity and build.
pub struct AttestationClaims {
    pub subject_role: String,
    pub issuer: String,
    pub build_digest: String,
    pub container_digest: Option<String>,
    pub boot_epoch: u64,
}

/// Produces an environment attestation for an actor (§27). The `statement` tier
/// implementation is [`StatementAttester`]; a future `tee` tier (L4) would be a
/// second implementor.
pub trait Attester {
    /// Produce a signed statement bound to the Gateway-issued `nonce`, valid until
    /// `expires_at`.
    fn attest(&self, nonce: &str, expires_at: &str) -> EnvironmentStatement;
}

/// The default-capable `statement`-tier [`Attester`] (§27.3): signs an
/// [`EnvironmentStatement`] with the Ed25519 key the actor already holds.
pub struct StatementAttester<'a> {
    claims: AttestationClaims,
    signer: &'a dyn Signer,
}

impl<'a> StatementAttester<'a> {
    /// Bind an actor's claims to its signing key.
    pub fn new(claims: AttestationClaims, signer: &'a dyn Signer) -> Self {
        Self { claims, signer }
    }
}

impl Attester for StatementAttester<'_> {
    fn attest(&self, nonce: &str, expires_at: &str) -> EnvironmentStatement {
        let mut stmt = EnvironmentStatement {
            kind: "vcp.environment.attestation".to_string(),
            tier: "statement".to_string(),
            subject_role: self.claims.subject_role.clone(),
            issuer: self.claims.issuer.clone(),
            build_digest: self.claims.build_digest.clone(),
            container_digest: self.claims.container_digest.clone(),
            boot_epoch: self.claims.boot_epoch,
            nonce: nonce.to_string(),
            expires_at: expires_at.to_string(),
            signature: None,
        };
        let value = self.signer.sign(stmt.signing_bytes().as_bytes());
        stmt.signature = Some(StatementSignature {
            alg: self.signer.alg().to_string(),
            value,
        });
        stmt
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::{Ed25519Signer, Ed25519Verifier, Verifier};

    #[test]
    fn statement_is_signed_and_verifies() {
        let signer = Ed25519Signer::from_label("provider-env");
        let attester = StatementAttester::new(
            AttestationClaims {
                subject_role: "provider".to_string(),
                issuer: "did:web:provider.example".to_string(),
                build_digest: "sha256:abab".to_string(),
                container_digest: None,
                boot_epoch: 7,
            },
            &signer,
        );
        let stmt = attester.attest("nonce-1", "2026-06-13T16:30:00Z");
        assert_eq!(stmt.kind, "vcp.environment.attestation");
        assert_eq!(stmt.tier, "statement");
        assert_eq!(stmt.subject_role, "provider");
        assert_eq!(stmt.nonce, "nonce-1");
        assert_eq!(stmt.expires_at, "2026-06-13T16:30:00Z");

        let verifier = Ed25519Verifier::from_signer(&signer);
        let sig = stmt.signature.as_ref().unwrap();
        assert_eq!(sig.alg, "Ed25519");
        assert!(verifier.verify(stmt.signing_bytes().as_bytes(), &sig.value));
        // Tampering with the bound nonce breaks the signature.
        let mut tampered = stmt.clone();
        tampered.nonce = "stale".to_string();
        assert!(!verifier.verify(tampered.signing_bytes().as_bytes(), &sig.value));
    }
}
