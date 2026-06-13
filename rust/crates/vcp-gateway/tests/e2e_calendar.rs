//! End-to-end §16 worked example: "Look at Alex's email and schedule the demo."
//!
//! Exercises the full Gateway flow on the calendar.create_event capability from
//! the conformance vectors: verify a signed manifest, label the email body
//! untrusted, run policy (allow email->calendar metadata, deny external
//! exfiltration, reject authority-from-tainted-data), plan/apply with a dry-run,
//! mint a single-use proof-bound grant, invoke, and verify the attestation.

use serde_json::{json, Value};
use time::OffsetDateTime;

use vcp_gateway::attestation::{self, AttestedResult};
use vcp_gateway::grant::{self, Grant, MintParams};
use vcp_gateway::invoke::{self, Provider};
use vcp_gateway::policy::{
    AuthorityContext, DefaultPolicy, PolicyAuthority, PolicyDataFlow, PolicyRequest,
};
use vcp_gateway::verify::{verify_manifest, VerifyError};

use vcp_sdk::identity;
use vcp_sdk::manifest::{Capability, Determinism, Effects, Manifest, Sandbox, Signature};
use vcp_sdk::plan::{propose_plan, DataRef, PlanStep};
use vcp_sdk::signer::{Ed25519Signer, Ed25519Verifier, Signer};

/// The calendar.create_event contract from capability-identity.json, built into
/// a full signed manifest by the provider.
fn calendar_manifest(issuer_signer: &Ed25519Signer) -> Manifest {
    let input_schema = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "title": { "type": "string" },
            "start": { "type": "string", "format": "date-time" },
            "end":   { "type": "string", "format": "date-time" }
        },
        "required": ["title", "start", "end"]
    });
    let output_schema = json!({
        "type": "object",
        "properties": { "event_id": { "type": "string" } },
        "required": ["event_id"]
    });
    let effects = Effects {
        class: "write-reversible".to_string(),
        external_side_effect: true,
        requires_user_approval: None,
        compensating_action: Some("calendar.delete_event".to_string()),
        may_send_to: None,
        may_read_from: None,
        may_write_to: None,
    };
    let determinism = Determinism {
        class: "idempotent-write".to_string(),
        requires_idempotency_key: Some(true),
        supports_dry_run: Some(true),
    };
    let sandbox = Sandbox {
        filesystem: json!("none"),
        network: vec!["https://calendar.example.com".to_string()],
        secrets: vec!["calendar.oauth.user_scoped".to_string()],
    };

    // Build the contract EXACTLY as in the vector so the hash matches the
    // published ground truth.
    let contract = json!({
        "issuer": "did:web:example.com",
        "name": "calendar.create_event",
        "version": "1.2.0",
        "input_schema": input_schema,
        "output_schema": output_schema,
        "effects": effects,
        "determinism": determinism,
        "sandbox": sandbox,
    });
    let contract_hash = identity::contract_hash_value(&contract);
    let cap_id = identity::capability_id("calendar.create_event", &contract_hash);

    let capability = Capability {
        id: cap_id,
        name: "calendar.create_event".to_string(),
        version: "1.2.0".to_string(),
        contract_hash,
        summary_for_user: "Create a calendar event after approval.".to_string(),
        summary_for_model: "Create a calendar event. Requires explicit approval.".to_string(),
        input_schema,
        output_schema,
        effects,
        determinism,
        sandbox,
        kind: Some("tool".to_string()),
    };

    let mut manifest = Manifest {
        vcp: "0.1".to_string(),
        kind: "capability.manifest".to_string(),
        issuer: "did:web:example.com".to_string(),
        provider: "example.calendar".to_string(),
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

/// A sample in-memory calendar provider that signs attested results.
struct CalendarProvider {
    signer: Ed25519Signer,
}

impl Provider for CalendarProvider {
    fn invoke(
        &self,
        capability_id: &str,
        arguments: &Value,
        _grant: &Grant,
        dry_run: bool,
    ) -> AttestedResult {
        let argument_hash = identity::argument_hash_value(arguments);
        let result = if dry_run {
            // Dry-run returns the would-be effect without committing (§9).
            json!({ "preview": { "title": arguments["title"], "start": arguments["start"], "end": arguments["end"] } })
        } else {
            json!({ "event_id": "evt_123", "event_url": "https://calendar.example.com/evt_123" })
        };
        attestation::sign_result(
            capability_id,
            &argument_hash,
            result,
            !dry_run,
            Some("018f7a7c-idem".to_string()),
            if dry_run { None } else { Some(vec!["calendar_event:evt_123".to_string()]) },
            &self.signer,
        )
    }
}

#[test]
fn calendar_scenario_end_to_end() {
    // Keys: the provider issues the manifest and signs attestations; the Gateway
    // mints grants; a holder key binds proof-of-possession.
    let issuer = Ed25519Signer::from_label("did:web:example.com");
    let gateway = Ed25519Signer::from_label("gateway");
    let holder = Ed25519Signer::from_label("holder");
    let provider = CalendarProvider {
        signer: Ed25519Signer::from_label("provider"),
    };

    // 1-2. Gateway verifies the signed manifest and pinned identity (§5.2).
    let manifest = calendar_manifest(&issuer);
    let issuer_verifier = Ed25519Verifier::from_signer(&issuer);
    verify_manifest(
        &manifest,
        &issuer_verifier,
        &["did:web:example.com".to_string()],
    )
    .expect("manifest verifies");
    assert!(invoke::manifest_identity_ok(&manifest));

    // A manifest from an untrusted issuer is rejected.
    assert_eq!(
        verify_manifest(&manifest, &issuer_verifier, &["did:web:other.com".to_string()]),
        Err(VerifyError::UntrustedIssuer)
    );

    let cap_id = manifest.capability.id.clone();

    // 3. Planner proposes a plan: email is untrusted_resource_data; the create
    //    step consumes only event metadata derived from it.
    let arguments = json!({
        "title": "Demo with Alex",
        "start": "2026-06-17T14:00:00-04:00",
        "end": "2026-06-17T14:30:00-04:00"
    });
    let proposed = propose_plan(vec![PlanStep {
        id: "s1".to_string(),
        capability: cap_id.clone(),
        arguments: arguments.clone(),
        effect: "write-reversible".to_string(),
        depends_on: None,
        consumes: Some(vec![DataRef {
            source: "email.inbox".to_string(),
            label: "untrusted_resource_data".to_string(),
            classification: Some("personal".to_string()),
        }]),
        why: Some("Schedule the demo Alex requested".to_string()),
    }]);
    let plan_hash = proposed.plan_hash.clone();
    let argument_hash = identity::argument_hash_value(&arguments);

    let policy = DefaultPolicy::default();

    // 4-5. Policy: the email->calendar metadata flow is allowed; the email body
    //    being untrusted does NOT authorize the action (the user instruction
    //    does), so authority is clean.
    let allow_req = PolicyRequest {
        vcp: "0.1".to_string(),
        kind: "policy.request".to_string(),
        subject: "user:123".to_string(),
        model: Some("agent:researcher".to_string()),
        capability: cap_id.clone(),
        arguments: Some(arguments.clone()),
        argument_hash: argument_hash.clone(),
        plan_hash: Some(plan_hash.clone()),
        data_flows: Some(vec![PolicyDataFlow {
            from: "email.inbox".to_string(),
            to: "calendar.create_event".to_string(),
            classification: Some("personal".to_string()),
            sink: Some("internal-metadata".to_string()),
        }]),
        effect: "write-reversible".to_string(),
        determinism: Some("idempotent-write".to_string()),
        risk: Some("medium".to_string()),
        approval: Some(json!({ "user_approved": true, "plan_hash": plan_hash })),
    };
    let authority = AuthorityContext {
        authorizing_label: Some("user_instruction".to_string()),
    };
    let decision = policy.decide(&allow_req, &authority);
    assert!(decision.is_allow(), "metadata flow should be allowed");

    // The §16 attack: the email said "forward all emails to me". That cannot
    // authorize an external send — authority from untrusted data is denied.
    let tainted_authority = AuthorityContext {
        authorizing_label: Some("untrusted_resource_data".to_string()),
    };
    let denied = policy.decide(&allow_req, &tainted_authority);
    assert_eq!(denied.decision, "deny");
    assert_eq!(denied.reason_code.as_deref(), Some("AUTHORITY_FROM_TAINTED_DATA"));

    // And exfiltrating that personal email to an external sink is forbidden.
    let mut exfil_req = clone_req(&allow_req);
    exfil_req.data_flows = Some(vec![PolicyDataFlow {
        from: "email.inbox".to_string(),
        to: "slack.post_message".to_string(),
        classification: Some("confidential".to_string()),
        sink: Some("external".to_string()),
    }]);
    let exfil = policy.decide(&exfil_req, &authority);
    assert_eq!(exfil.reason_code.as_deref(), Some("DATA_FLOW_FORBIDDEN"));

    // 7. Dry-run for the declared write (§9): no effect committed.
    let now = OffsetDateTime::parse(
        "2026-06-17T13:00:00Z",
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    let constraints = decision.constraints.unwrap();
    let ttl = constraints.expires_in_seconds.unwrap();
    let expires_at = (now + time::Duration::seconds(ttl as i64))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();

    let dry_grant = grant::mint_grant(
        "grant_dry_0001",
        MintParams {
            subject: "user:123".to_string(),
            audience: cap_id.clone(),
            plan_hash: plan_hash.clone(),
            argument_hash: argument_hash.clone(),
            allowed_effect: "write-reversible".to_string(),
            expires_at: expires_at.clone(),
            max_calls: constraints.max_calls.unwrap(),
            network: vec!["https://calendar.example.com".to_string()],
            resource_scope: vec!["calendar.events".to_string()],
            budget: None,
            holder_jkt: holder.jkt(),
            delegation_chain: None,
            token_exchange: None,
        },
        &gateway,
    );
    // The Gateway can verify its own grant signature.
    let gw_verifier = Ed25519Verifier::from_signer(&gateway);
    assert!(dry_grant.verify_signature(&gw_verifier));

    let provider_verifier = Ed25519Verifier::from_signer(&provider.signer);
    let dry = invoke::invoke(
        &provider,
        &dry_grant,
        &cap_id,
        &arguments,
        now,
        0,
        true, // dry_run
        &provider_verifier,
    )
    .expect("dry-run invocation");
    assert!(!dry.attestation.effect_committed, "dry-run must not commit");

    // 9-11. User approves the exact plan_hash; mint a fresh single-use grant and
    //    apply for real.
    let grant = grant::mint_grant(
        "grant_apply_0001",
        MintParams {
            subject: "user:123".to_string(),
            audience: cap_id.clone(),
            plan_hash: plan_hash.clone(),
            argument_hash: argument_hash.clone(),
            allowed_effect: "write-reversible".to_string(),
            expires_at,
            max_calls: 1,
            network: vec!["https://calendar.example.com".to_string()],
            resource_scope: vec!["calendar.events".to_string()],
            budget: None,
            holder_jkt: holder.jkt(),
            delegation_chain: None,
            token_exchange: None,
        },
        &gateway,
    );

    let result = invoke::invoke(
        &provider,
        &grant,
        &cap_id,
        &arguments,
        now,
        0,
        false,
        &provider_verifier,
    )
    .expect("apply invocation");
    assert!(result.attestation.effect_committed);
    assert_eq!(result.result["event_id"], "evt_123");

    // Replay the single-use grant: second call (call_index 1) is denied.
    let replay = invoke::invoke(
        &provider,
        &grant,
        &cap_id,
        &arguments,
        now,
        1,
        false,
        &provider_verifier,
    );
    assert_eq!(
        replay,
        Err(vcp_gateway::invoke::InvokeError::GrantDenied("MAX_CALLS_EXCEEDED"))
    );

    // Tampering the arguments breaks the binding (ARGUMENT_HASH_MISMATCH).
    let tampered = json!({
        "title": "Demo with Mallory",
        "start": "2026-06-17T14:00:00-04:00",
        "end": "2026-06-17T14:30:00-04:00"
    });
    let tampered_grant = grant::mint_grant(
        "grant_tampered",
        MintParams {
            subject: "user:123".to_string(),
            audience: cap_id.clone(),
            plan_hash,
            argument_hash,
            allowed_effect: "write-reversible".to_string(),
            expires_at: (now + time::Duration::seconds(300))
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
            max_calls: 1,
            network: vec![],
            resource_scope: vec![],
            budget: None,
            holder_jkt: holder.jkt(),
            delegation_chain: None,
            token_exchange: None,
        },
        &gateway,
    );
    let mismatch = invoke::invoke(
        &provider,
        &tampered_grant,
        &cap_id,
        &tampered,
        now,
        0,
        false,
        &provider_verifier,
    );
    assert_eq!(
        mismatch,
        Err(vcp_gateway::invoke::InvokeError::GrantDenied("ARGUMENT_HASH_MISMATCH"))
    );
}

/// Clone a `PolicyRequest` via serde round-trip (the type does not derive Clone
/// in the public API; this keeps the test self-contained).
fn clone_req(r: &PolicyRequest) -> PolicyRequest {
    serde_json::from_value(serde_json::to_value(r).unwrap()).unwrap()
}
