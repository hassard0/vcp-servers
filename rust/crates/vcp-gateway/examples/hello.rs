//! Zero-to-working VCP example: build + sign a capability manifest, then drive it
//! end to end through the Gateway.
//!
//! Run it with:
//!
//! ```text
//! cargo run -p vcp-gateway --example hello
//! ```
//!
//! This is the smallest complete VCP flow. It plays all four roles in one process
//! so you can see the whole protocol at a glance:
//!
//!   1. A **Provider** authors a capability `Contract`, derives its
//!      content-addressed `capability_id`, wraps it in a signed `Manifest`, and
//!      stands up a tiny in-process implementation of the capability.
//!   2. The **Gateway** (the only actor with authority) verifies the manifest,
//!      asks a `PolicyAuthority` for a decision, mints a single-use,
//!      proof-of-possession-bound `Grant`, and drives the invocation.
//!   3. The Provider returns a signed result **attestation**; the Gateway verifies
//!      it before releasing the result.
//!
//! We deliberately use a **read-only** capability (`weather.current`) with no
//! external side effect, so policy allows it with no user approval and no
//! environment attestation — the shortest happy path.

use serde_json::{json, Value};
use time::OffsetDateTime;

// --- Gateway (authority) side ---
use vcp_gateway::attestation::{self, AttestedResult};
use vcp_gateway::grant::{self, Grant, MintParams};
use vcp_gateway::invoke::{self, Provider};
use vcp_gateway::policy::{AuthorityContext, DefaultPolicy, PolicyAuthority, PolicyRequest};
use vcp_gateway::verify::verify_manifest;

// --- SDK (Planner / Provider) side ---
use vcp_sdk::identity;
use vcp_sdk::manifest::{Capability, Contract, Determinism, Effects, Manifest, Sandbox, Signature};
use vcp_sdk::signer::{Ed25519Signer, Ed25519Verifier, Signer};

/// Author the `weather.current` capability contract and wrap it in a manifest
/// signed by the issuer. The contract is the *security-relevant* subset of the
/// manifest (§4): change any field and the identity changes.
fn weather_manifest(issuer_signer: &Ed25519Signer) -> Manifest {
    // The JSON Schemas describe the capability's inputs and outputs. They are part
    // of the contract, so they feed into the content-addressed identity.
    let input_schema = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": { "city": { "type": "string" } },
        "required": ["city"]
    });
    let output_schema = json!({
        "type": "object",
        "properties": {
            "city":    { "type": "string" },
            "temp_c":  { "type": "number" },
            "summary": { "type": "string" }
        },
        "required": ["city", "temp_c", "summary"]
    });

    // Read-only, no external side effect: this is what keeps the path approval-free.
    let effects = Effects {
        class: "read-only".to_string(),
        external_side_effect: false,
        requires_user_approval: None,
        requires_attestation: None,
        compensating_action: None,
        may_send_to: None,
        may_read_from: None,
        may_write_to: None,
    };
    let determinism = Determinism {
        class: "deterministic".to_string(),
        requires_idempotency_key: None,
        supports_dry_run: None,
    };
    let sandbox = Sandbox {
        filesystem: json!("none"),
        network: vec!["https://weather.example.com".to_string()],
        secrets: vec![],
    };

    // The contract defines identity. We build it as a typed value and let the SDK
    // compute contract_hash = sha256(JCS(contract)) and capability_id (§4).
    let contract = Contract {
        issuer: "did:web:weather.example".to_string(),
        name: "weather.current".to_string(),
        version: "1.0.0".to_string(),
        input_schema: input_schema.clone(),
        output_schema: output_schema.clone(),
        effects: effects.clone(),
        determinism: determinism.clone(),
        sandbox: sandbox.clone(),
    };
    let contract_hash = contract.contract_hash();
    let capability_id = contract.capability_id();

    // The capability body carries the contract fields plus human/model display
    // strings and the pinned content-addressed id.
    let capability = Capability {
        id: capability_id,
        name: "weather.current".to_string(),
        version: "1.0.0".to_string(),
        contract_hash,
        summary_for_user: "Look up the current weather for a city.".to_string(),
        summary_for_model: "Read-only current weather by city name.".to_string(),
        input_schema,
        output_schema,
        effects,
        determinism,
        sandbox,
        kind: Some("tool".to_string()),
    };

    // Assemble the manifest, then sign JCS(manifest without signature) (§3).
    let mut manifest = Manifest {
        vcp: "0.1".to_string(),
        kind: "capability.manifest".to_string(),
        issuer: "did:web:weather.example".to_string(),
        provider: "example.weather".to_string(),
        capability,
        provenance: None,
        signature: Signature {
            alg: issuer_signer.alg().to_string(),
            value: String::new(),
        },
    };
    manifest.signature.value = issuer_signer.sign(manifest.signing_bytes().as_bytes());
    manifest
}

/// A tiny in-process provider that implements `weather.current`. It executes
/// within the grant's bounds and signs an attestation over its result (§9).
struct WeatherProvider {
    signer: Ed25519Signer,
}

impl Provider for WeatherProvider {
    fn invoke(
        &self,
        capability_id: &str,
        arguments: &Value,
        _grant: &Grant,
        _dry_run: bool,
    ) -> AttestedResult {
        // The provider recomputes argument_hash and binds it into the attestation.
        let argument_hash = identity::argument_hash_value(arguments);
        let city = arguments["city"].as_str().unwrap_or("unknown");
        let result = json!({
            "city": city,
            "temp_c": 18.5,
            "summary": "Partly cloudy"
        });
        // sign_result produces a Provider-signed AttestedResult: result + an
        // attestation binding capability_id, argument_hash, and result_hash.
        attestation::sign_result(
            capability_id,
            &argument_hash,
            result,
            false, // effect_committed: a read has no committed external effect
            None,  // no idempotency key for a read
            None,  // no observed external refs
            &self.signer,
        )
    }
}

fn main() {
    // Four keys for the four roles. `from_label` derives a deterministic dev key
    // from a string — convenient for examples, NOT for production.
    let issuer = Ed25519Signer::from_label("did:web:weather.example");
    let gateway = Ed25519Signer::from_label("gateway");
    let holder = Ed25519Signer::from_label("holder");
    let provider = WeatherProvider {
        signer: Ed25519Signer::from_label("provider"),
    };

    // === Provider: build and sign the manifest ===
    let manifest = weather_manifest(&issuer);
    let capability_id = manifest.capability.id.clone();
    println!("capability_id: {capability_id}");

    // === Gateway step 1: verify the signed, content-addressed manifest (§5.2) ===
    // The Gateway checks the issuer signature, recomputes contract_hash, and
    // confirms the id pins that hash — and that the issuer is trusted.
    let issuer_verifier = Ed25519Verifier::from_signer(&issuer);
    verify_manifest(
        &manifest,
        &issuer_verifier,
        &["did:web:weather.example".to_string()],
    )
    .expect("manifest must verify");
    println!("manifest verified: signature OK, contract_hash pinned, issuer trusted");

    // === Planner: choose arguments and bind them (§7/§8) ===
    let arguments = json!({ "city": "Reykjavik" });
    let argument_hash = identity::argument_hash_value(&arguments);
    // A trivial single-step "plan". A real Planner would hash a full plan; here a
    // stable placeholder is enough to bind the grant to.
    let plan_hash = "sha256:example-plan".to_string();

    // === Gateway step 2: get a mandatory policy decision (§6) ===
    // Authority comes from a clean source (a user instruction), not from any
    // tainted/untrusted data — so the taint-aware DefaultPolicy allows it.
    let policy = DefaultPolicy::default();
    let request = PolicyRequest {
        vcp: "0.1".to_string(),
        kind: "policy.request".to_string(),
        subject: "user:alice".to_string(),
        model: Some("agent:assistant".to_string()),
        capability: capability_id.clone(),
        arguments: Some(arguments.clone()),
        argument_hash: argument_hash.clone(),
        plan_hash: Some(plan_hash.clone()),
        data_flows: None,
        effect: "read-only".to_string(),
        determinism: Some("deterministic".to_string()),
        risk: Some("low".to_string()),
        approval: None,
    };
    let authority = AuthorityContext {
        authorizing_label: Some("user_instruction".to_string()),
    };
    let decision = policy.decide(&request, &authority);
    assert!(decision.is_allow(), "read-only request should be allowed");
    let constraints = decision.constraints.expect("allow carries constraints");
    println!(
        "policy decision: allow ({})",
        decision.reason_code.as_deref().unwrap_or("")
    );

    // === Gateway step 3: mint a single-use, proof-bound grant (§7) ===
    // Authority is created here and only here, after the policy allow. The grant
    // is bound to audience (the exact capability_id), argument_hash, plan_hash,
    // an expiry, max_calls, and the holder's key (proof-of-possession).
    let now = OffsetDateTime::now_utc();
    let ttl = constraints.expires_in_seconds.unwrap_or(300);
    let expires_at = (now + time::Duration::seconds(ttl as i64))
        .format(&time::format_description::well_known::Rfc3339)
        .expect("format expiry");
    let g = grant::mint_grant(
        "grant_hello_0001",
        MintParams {
            subject: "user:alice".to_string(),
            audience: capability_id.clone(),
            plan_hash,
            argument_hash,
            allowed_effect: "read-only".to_string(),
            expires_at,
            max_calls: constraints.max_calls.unwrap_or(1),
            network: vec!["https://weather.example.com".to_string()],
            resource_scope: vec![],
            budget: None,
            holder_jkt: holder.jkt(),
            delegation_chain: None,
            token_exchange: None,
            attestation_ref: None,
        },
        &gateway,
    );
    // The Gateway can verify its own signature over the grant.
    let gateway_verifier = Ed25519Verifier::from_signer(&gateway);
    assert!(g.verify_signature(&gateway_verifier), "grant signature OK");
    println!("grant minted: {} (single-use, expires {})", g.grant_id, g.expires_at);

    // === Gateway step 4: invoke end to end (§8/§9) ===
    // invoke() re-checks the grant against the attempt, calls the provider, then
    // verifies the returned attestation BEFORE releasing the result. call_index 0
    // means this is the first (and, with max_calls = 1, only) use.
    let provider_verifier = Ed25519Verifier::from_signer(&provider.signer);
    let attested = invoke::invoke(
        &provider,
        &g,
        &capability_id,
        &arguments,
        now,
        0,     // call_index: first use
        false, // dry_run
        &provider_verifier,
    )
    .expect("invocation should succeed and attestation should verify");

    // The result is only released because the attestation verified: the signature
    // is valid and capability_id / argument_hash / result_hash all match.
    println!("attestation verified: provider signature OK, hashes match");
    let r = &attested.result;
    println!(
        "result: {} is {}\u{00b0}C, {}",
        r["city"].as_str().unwrap_or(""),
        r["temp_c"],
        r["summary"].as_str().unwrap_or("")
    );

    // Replaying the single-use grant (call_index 1) is denied — proving the grant
    // is genuinely single-use.
    let replay = invoke::invoke(
        &provider,
        &g,
        &capability_id,
        &arguments,
        now,
        1, // second use
        false,
        &provider_verifier,
    );
    assert!(replay.is_err(), "single-use grant cannot be replayed");
    println!("replay denied: grant is single-use, as expected");
}
