//! Conformance + security tests for environment attestation (§27).
//!
//! - drives every case in `conformance/vectors/environment-attestation.json`
//!   through `verify_environment_attestation` (§27.4);
//! - security test 19: a capability whose `effects.requires_attestation` is true
//!   mints **no grant** without a valid environment statement, and mints one
//!   (with an `attestation_ref`) when a valid statement is presented;
//! - a normal capability (no attestation required) still mints unchanged, with no
//!   `attestation_ref`.
//!
//! Vector paths resolve via `CARGO_MANIFEST_DIR` so the test runs from any cwd.

use serde_json::Value;
use std::path::PathBuf;

use vcp_gateway::audit::attested_audit_event;
use vcp_gateway::env_attestation::verify_environment_attestation;
use vcp_gateway::grant::{mint_grant_gated, parse_rfc3339, Decision, MintParams};

use vcp_sdk::attestation::{
    AttestationClaims, Attester, EnvironmentStatement, StatementAttester, StatementSignature,
};
use vcp_sdk::signer::{Ed25519Signer, Ed25519Verifier};

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join("conformance")
        .join("vectors")
}

fn load(name: &str) -> Value {
    let path = vectors_dir().join(name);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_slice(&bytes).expect("vector is valid JSON")
}

fn decision_str(d: &Decision) -> &'static str {
    match d {
        Decision::Allow => "allow",
        Decision::Deny => "deny",
    }
}

/// Build an `EnvironmentStatement` from the partial JSON a vector case carries.
/// The vector's statements omit `issuer`/`boot_epoch`/`signature` (the §27.4
/// verdict turns only on tier/role/build/nonce/expiry), so fill sensible
/// defaults for the unrelated fields.
fn statement_from_case(j: &Value) -> EnvironmentStatement {
    EnvironmentStatement {
        kind: "vcp.environment.attestation".to_string(),
        tier: j["tier"].as_str().unwrap().to_string(),
        subject_role: j["subject_role"].as_str().unwrap().to_string(),
        issuer: "did:web:provider.example".to_string(),
        build_digest: j["build_digest"].as_str().unwrap().to_string(),
        container_digest: None,
        boot_epoch: 1,
        nonce: j["nonce"].as_str().unwrap().to_string(),
        expires_at: j["expires_at"].as_str().unwrap().to_string(),
        signature: None,
    }
}

// ----------------------------------------------------------------------------
// §27.4 — environment-attestation verdict vector
// ----------------------------------------------------------------------------

#[test]
fn environment_attestation_vector() {
    let v = load("environment-attestation.json");
    let challenge_nonce = v["challenge_nonce"].as_str().unwrap();
    let now = parse_rfc3339(v["now"].as_str().unwrap()).expect("now parses");
    let trusted: Vec<String> = v["trusted_build_digests"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d.as_str().unwrap().to_string())
        .collect();

    for case in v["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let requires = case["requires_attestation"].as_bool().unwrap();
        let stmt = if case["statement"].is_null() {
            None
        } else {
            Some(statement_from_case(&case["statement"]))
        };

        let (decision, reason) =
            verify_environment_attestation(stmt.as_ref(), requires, challenge_nonce, now, &trusted);

        let expect = &case["expect"];
        assert_eq!(
            decision_str(&decision),
            expect["decision"].as_str().unwrap(),
            "decision mismatch in {name}"
        );
        assert_eq!(
            reason.as_str(),
            expect["reason_code"].as_str().unwrap(),
            "reason_code mismatch in {name}"
        );
    }
}

// ----------------------------------------------------------------------------
// Security test 19 (§18 / §27) — requires_attestation gates grant minting
// ----------------------------------------------------------------------------

/// A signing actor whose build is trusted, plus the Gateway's challenge context.
struct Fixture {
    gateway_signer: Ed25519Signer,
    provider_env_signer: Ed25519Signer,
    trusted: Vec<String>,
    challenge_nonce: String,
    now: time::OffsetDateTime,
}

impl Fixture {
    fn new() -> Self {
        Self {
            gateway_signer: Ed25519Signer::from_label("gateway"),
            provider_env_signer: Ed25519Signer::from_label("provider-env"),
            trusted: vec![
                "sha256:abababababababababababababababababababababababababababababababab"
                    .to_string(),
            ],
            challenge_nonce: "nonce-abc-123".to_string(),
            now: parse_rfc3339("2026-06-13T16:00:00Z").unwrap(),
        }
    }

    /// A valid, signed provider environment statement bound to the challenge.
    fn valid_statement(&self) -> EnvironmentStatement {
        StatementAttester::new(
            AttestationClaims {
                subject_role: "provider".to_string(),
                issuer: "did:web:provider.example".to_string(),
                build_digest: self.trusted[0].clone(),
                container_digest: None,
                boot_epoch: 9,
            },
            &self.provider_env_signer,
        )
        .attest(&self.challenge_nonce, "2026-06-13T16:30:00Z")
    }

    fn params(&self) -> MintParams {
        MintParams {
            subject: "user:123".to_string(),
            audience: "vcp:cap:secure.write@sha256:deadbeef".to_string(),
            plan_hash: "sha256:plan".to_string(),
            argument_hash: "sha256:args".to_string(),
            allowed_effect: "write-reversible".to_string(),
            expires_at: "2026-06-13T16:05:00Z".to_string(),
            holder_jkt: "sha256:holder".to_string(),
            ..MintParams::default()
        }
    }
}

#[test]
fn security_19_required_no_statement_mints_no_grant() {
    let f = Fixture::new();
    let env_verifier = Ed25519Verifier::from_signer(&f.provider_env_signer);

    // requires_attestation = true, but no statement presented.
    let (decision, reason, grant) = mint_grant_gated(
        "grant_sec19_missing",
        f.params(),
        &f.gateway_signer,
        None,
        true,
        &f.challenge_nonce,
        f.now,
        &f.trusted,
        &env_verifier,
    );

    assert_eq!(decision, Decision::Deny);
    assert_eq!(reason, "ATTESTATION_REQUIRED");
    assert!(grant.is_none(), "no grant may be minted without attestation");
}

#[test]
fn security_19_required_invalid_statement_mints_no_grant() {
    let f = Fixture::new();
    let env_verifier = Ed25519Verifier::from_signer(&f.provider_env_signer);

    // A statement bound to the WRONG nonce (forged/stale) ⇒ ATTESTATION_INVALID.
    let mut stale = f.valid_statement();
    stale.nonce = "stale-nonce".to_string();
    // Re-sign so the signature itself is valid; the nonce mismatch is the defect.
    let sig = f.provider_env_signer_sign(&stale);
    let stale = EnvironmentStatement {
        signature: Some(sig),
        ..stale
    };

    let (decision, reason, grant) = mint_grant_gated(
        "grant_sec19_stale",
        f.params(),
        &f.gateway_signer,
        Some(&stale),
        true,
        &f.challenge_nonce,
        f.now,
        &f.trusted,
        &env_verifier,
    );

    assert_eq!(decision, Decision::Deny);
    assert_eq!(reason, "ATTESTATION_INVALID");
    assert!(grant.is_none());

    // And a forged signature (right nonce, wrong signing key) is also rejected.
    let forger = Ed25519Signer::from_label("forger");
    let forged = StatementAttester::new(
        AttestationClaims {
            subject_role: "provider".to_string(),
            issuer: "did:web:provider.example".to_string(),
            build_digest: f.trusted[0].clone(),
            container_digest: None,
            boot_epoch: 9,
        },
        &forger,
    )
    .attest(&f.challenge_nonce, "2026-06-13T16:30:00Z");

    let (decision, reason, grant) = mint_grant_gated(
        "grant_sec19_forged",
        f.params(),
        &f.gateway_signer,
        Some(&forged),
        true,
        &f.challenge_nonce,
        f.now,
        &f.trusted,
        &env_verifier, // verifies against the genuine provider key, not the forger
    );
    assert_eq!(decision, Decision::Deny);
    assert_eq!(reason, "ATTESTATION_INVALID");
    assert!(grant.is_none());
}

#[test]
fn security_19_required_valid_statement_mints_grant_with_ref() {
    let f = Fixture::new();
    let env_verifier = Ed25519Verifier::from_signer(&f.provider_env_signer);
    let stmt = f.valid_statement();

    let (decision, reason, grant) = mint_grant_gated(
        "grant_sec19_valid",
        f.params(),
        &f.gateway_signer,
        Some(&stmt),
        true,
        &f.challenge_nonce,
        f.now,
        &f.trusted,
        &env_verifier,
    );

    assert_eq!(decision, Decision::Allow);
    assert_eq!(reason, "OK");
    let grant = grant.expect("a valid statement mints a grant");

    // The attestation reference is attached by reference (§27.2): id + bound nonce.
    let att_ref = grant
        .attestation_ref
        .as_ref()
        .expect("attestation_ref attached on a gated grant");
    assert_eq!(att_ref.nonce, f.challenge_nonce);
    assert!(att_ref.id.contains("did:web:provider.example"));

    // The grant is signed and verifies (the gate did not corrupt minting).
    let gw_verifier = Ed25519Verifier::from_signer(&f.gateway_signer);
    assert!(grant.verify_signature(&gw_verifier));

    // §27.4 step 4: the audit event records the attestation result by reference.
    let event = attested_audit_event(
        "vcp.capability.invoked",
        "trace-1",
        &grant.subject,
        &grant.audience,
        "allow",
        "OK",
        att_ref.clone(),
        "2026-06-13T16:00:01Z",
        &f.gateway_signer,
    );
    assert_eq!(
        event.attestation_ref.as_ref().unwrap().nonce,
        f.challenge_nonce
    );
    assert!(event.signature.is_some());
}

// ----------------------------------------------------------------------------
// A normal capability still mints unchanged (zero friction, §27.1)
// ----------------------------------------------------------------------------

#[test]
fn normal_capability_mints_unchanged() {
    let f = Fixture::new();
    let env_verifier = Ed25519Verifier::from_signer(&f.provider_env_signer);

    // requires_attestation = false ⇒ no statement, no attestation_ref, allow.
    let (decision, reason, grant) = mint_grant_gated(
        "grant_normal",
        f.params(),
        &f.gateway_signer,
        None,
        false,
        &f.challenge_nonce,
        f.now,
        &f.trusted,
        &env_verifier,
    );

    assert_eq!(decision, Decision::Allow);
    assert_eq!(reason, "OK");
    let grant = grant.expect("normal capability mints a grant");
    assert!(
        grant.attestation_ref.is_none(),
        "no attestation_ref on the common path"
    );

    // Identical to a plain mint_grant: still single-use, audience-bound, signed.
    let gw_verifier = Ed25519Verifier::from_signer(&f.gateway_signer);
    assert!(grant.verify_signature(&gw_verifier));
    assert_eq!(grant.max_calls, 1);
    assert_eq!(grant.audience, "vcp:cap:secure.write@sha256:deadbeef");
}

impl Fixture {
    /// Sign a (possibly mutated) statement with the genuine provider env key.
    fn provider_env_signer_sign(&self, stmt: &EnvironmentStatement) -> StatementSignature {
        use vcp_sdk::signer::Signer;
        StatementSignature {
            alg: self.provider_env_signer.alg().to_string(),
            value: self
                .provider_env_signer
                .sign(stmt.signing_bytes().as_bytes()),
        }
    }
}
