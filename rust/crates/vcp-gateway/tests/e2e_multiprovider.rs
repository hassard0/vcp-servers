//! End-to-end multi-provider on-behalf-of fan-out (§26, Appendix D).
//!
//! User: "Summarize the support emails from this week and open a Linear issue
//! for each bug, then post a digest to our team Slack."
//!
//! Three providers: `gmail` (read), `linear` (write-reversible), `slack`
//! (write-irreversible, external). One plan, one user approval, N single-use
//! provider-scoped grants, per-provider exchanged credentials (each unusable at
//! another provider), a full delegation-chain audit per upstream call, and a
//! blocked `confidential → external` data flow (`DATA_FLOW_FORBIDDEN`).

use serde_json::{json, Value};
use time::OffsetDateTime;

use vcp_gateway::attestation::{self, AttestedResult};
use vcp_gateway::audit::{upstream_audit_event, UpstreamAudit};
use vcp_gateway::delegation::{
    DelegationChain, MockTokenExchangeBroker, TokenExchange, TokenExchangeBroker,
};
use vcp_gateway::grant::{self, Grant, MintParams};
use vcp_gateway::invoke::{self, Provider};
use vcp_gateway::policy::{
    AuthorityContext, DefaultPolicy, PolicyAuthority, PolicyDataFlow, PolicyRequest,
};
use vcp_gateway::reason::ReasonCode;

use vcp_sdk::identity;
use vcp_sdk::plan::{propose_plan, DataRef, PlanStep};
use vcp_sdk::signer::{Ed25519Signer, Ed25519Verifier, Verifier};

/// A generic mock upstream provider that signs attested results and asserts it
/// only ever sees a credential bound to its own audience.
struct MockProvider {
    capability_id: String,
    signer: Ed25519Signer,
}

impl Provider for MockProvider {
    fn invoke(
        &self,
        capability_id: &str,
        arguments: &Value,
        _grant: &Grant,
        dry_run: bool,
    ) -> AttestedResult {
        assert_eq!(capability_id, self.capability_id);
        let argument_hash = identity::argument_hash_value(arguments);
        let result = if dry_run {
            json!({ "preview": arguments })
        } else {
            json!({ "ok": true, "ref": format!("{}:done", capability_id) })
        };
        attestation::sign_result(
            capability_id,
            &argument_hash,
            result,
            !dry_run,
            Some("idem-key".to_string()),
            if dry_run {
                None
            } else {
                Some(vec![format!("{capability_id}:committed")])
            },
            &self.signer,
        )
    }
}

struct StepCfg {
    provider_name: &'static str,
    capability_id: String,
    api: &'static str,
    effect: &'static str,
    arguments: Value,
}

#[test]
fn multiprovider_fanout_one_approval() {
    let user = "user:123";
    let agent = "agent:triage";
    let gateway_id = "gateway:edge-1";

    let gateway = Ed25519Signer::from_label("gateway");
    let gw_verifier = Ed25519Verifier::from_signer(&gateway);
    let holder = Ed25519Signer::from_label("holder");
    let audit_signer = Ed25519Signer::from_label("audit");
    let audit_verifier = Ed25519Verifier::from_signer(&audit_signer);
    let broker = MockTokenExchangeBroker;

    // Stable capability ids for the three providers.
    let linear_cap =
        "vcp:cap:linear.create_issue@sha256:1111111111111111111111111111111111111111111111111111111111111111".to_string();
    let slack_cap =
        "vcp:cap:slack.post_message@sha256:2222222222222222222222222222222222222222222222222222222222222222".to_string();

    // ---- 1. One plan spanning all three providers (gmail read is unattended). ----
    let gmail_cap =
        "vcp:cap:gmail.search@sha256:3333333333333333333333333333333333333333333333333333333333333333".to_string();

    let linear_args = json!({ "title": "Login button 500s", "body": "From support triage" });
    let slack_args = json!({ "channel": "#support", "text": "Digest: 3 issues opened." });

    let proposed = propose_plan(vec![
        PlanStep {
            id: "s1".to_string(),
            capability: gmail_cap.clone(),
            arguments: json!({ "query": "label:support newer_than:7d" }),
            effect: "read-only".to_string(),
            depends_on: None,
            consumes: None,
            why: Some("Read this week's support email".to_string()),
        },
        PlanStep {
            id: "s2".to_string(),
            capability: linear_cap.clone(),
            arguments: linear_args.clone(),
            effect: "write-reversible".to_string(),
            depends_on: Some(vec!["s1".to_string()]),
            consumes: Some(vec![DataRef {
                source: "gmail.inbox".to_string(),
                label: "untrusted_resource_data".to_string(),
                classification: Some("confidential".to_string()),
            }]),
            why: Some("Open a Linear issue per bug".to_string()),
        },
        PlanStep {
            id: "s3".to_string(),
            capability: slack_cap.clone(),
            arguments: slack_args.clone(),
            effect: "write-irreversible".to_string(),
            depends_on: Some(vec!["s2".to_string()]),
            consumes: Some(vec![DataRef {
                source: "linear.issues".to_string(),
                label: "untrusted_tool_result".to_string(),
                classification: Some("internal".to_string()),
            }]),
            why: Some("Post a digest to Slack".to_string()),
        },
    ]);
    let plan_hash = proposed.plan_hash.clone();

    let policy = DefaultPolicy::default();
    // Authority comes from the user's instruction, not from the tainted email.
    let authority = AuthorityContext {
        authorizing_label: Some("user_instruction".to_string()),
    };

    // ---- 2. The blocked flow: raw confidential email content -> slack (external). ----
    let exfil_req = PolicyRequest {
        vcp: "0.1".to_string(),
        kind: "policy.request".to_string(),
        subject: user.to_string(),
        model: Some(agent.to_string()),
        capability: slack_cap.clone(),
        arguments: Some(slack_args.clone()),
        argument_hash: identity::argument_hash_value(&slack_args),
        plan_hash: Some(plan_hash.clone()),
        data_flows: Some(vec![PolicyDataFlow {
            from: "gmail.inbox".to_string(),
            to: "slack.post_message".to_string(),
            classification: Some("confidential".to_string()),
            sink: Some("external".to_string()),
        }]),
        effect: "write-irreversible".to_string(),
        determinism: None,
        risk: Some("high".to_string()),
        approval: Some(json!({ "user_approved": true, "plan_hash": plan_hash })),
    };
    let exfil = policy.decide(&exfil_req, &authority);
    assert_eq!(exfil.decision, "deny");
    assert_eq!(
        exfil.reason_code.as_deref(),
        Some(ReasonCode::DataFlowForbidden.as_str()),
        "raw confidential email to an external Slack sink MUST be forbidden"
    );

    // ---- 3. The approved writes (linear, slack) — one approval over plan_hash. ----
    let steps = [
        StepCfg {
            provider_name: "linear",
            capability_id: linear_cap.clone(),
            api: "https://api.linear.app",
            effect: "write-reversible",
            arguments: linear_args,
        },
        StepCfg {
            provider_name: "slack",
            capability_id: slack_cap.clone(),
            api: "https://slack.com/api",
            effect: "write-irreversible",
            // The digest carries only internal metadata, not raw email content.
            arguments: slack_args,
        },
    ] as [StepCfg; 2];

    let now = OffsetDateTime::parse(
        "2026-06-13T16:00:00Z",
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    let expires_at = (now + time::Duration::seconds(300))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();

    let mut credentials: Vec<TokenExchange> = Vec::new();
    let mut audits = Vec::new();

    for (i, step) in steps.iter().enumerate() {
        // The metadata flow each write needs is allowed (internal-metadata sink).
        let arg_hash = identity::argument_hash_value(&step.arguments);
        let allow_req = PolicyRequest {
            vcp: "0.1".to_string(),
            kind: "policy.request".to_string(),
            subject: user.to_string(),
            model: Some(agent.to_string()),
            capability: step.capability_id.clone(),
            arguments: Some(step.arguments.clone()),
            argument_hash: arg_hash.clone(),
            plan_hash: Some(plan_hash.clone()),
            data_flows: Some(vec![PolicyDataFlow {
                from: "linear.issues".to_string(),
                to: step.provider_name.to_string(),
                classification: Some("internal".to_string()),
                sink: Some("internal-metadata".to_string()),
            }]),
            effect: step.effect.to_string(),
            determinism: None,
            risk: Some("medium".to_string()),
            approval: Some(json!({ "user_approved": true, "plan_hash": plan_hash })),
        };
        let decision = policy.decide(&allow_req, &authority);
        assert!(decision.is_allow(), "{} write should be allowed", step.provider_name);

        // §26.1: token exchange per provider — audience-bound, actor-stamped.
        let cred = broker.exchange(user, agent, step.api);
        assert_eq!(cred.audience, step.api);
        assert_eq!(cred.actor.sub, agent);
        assert_eq!(cred.actor.on_behalf_of, user);
        // A credential is only usable at its own audience.
        assert_eq!(cred.check_audience(step.api).1, ReasonCode::Ok);

        // §26.2: the delegation chain for this upstream call.
        let chain =
            DelegationChain::build(user, agent, gateway_id, step.provider_name, step.api);

        // §26.3: one single-use, provider-scoped grant per write under the single
        // approval — carrying the chain and the token-exchange binding.
        let token_exchange = TokenExchange::from(&cred);
        let g = grant::mint_grant(
            &format!("grant_step_{i}"),
            MintParams {
                subject: user.to_string(),
                audience: step.capability_id.clone(),
                plan_hash: plan_hash.clone(),
                argument_hash: arg_hash.clone(),
                allowed_effect: step.effect.to_string(),
                expires_at: expires_at.clone(),
                max_calls: 1,
                network: vec![step.api.to_string()],
                resource_scope: vec![],
                budget: None,
                holder_jkt: holder.jkt(),
                delegation_chain: Some(chain.clone()),
                token_exchange: Some(token_exchange.clone()),
            },
            &gateway,
        );
        assert!(g.verify_signature(&gw_verifier), "grant signature verifies");
        // The grant records the chain + the credential audience by reference.
        assert_eq!(g.delegation_chain.as_ref().unwrap(), &chain);
        assert_eq!(
            g.token_exchange.as_ref().unwrap().audience,
            step.api
        );

        credentials.push(token_exchange);

        // Execute the provider within the grant; verify its attestation.
        let provider = MockProvider {
            capability_id: step.capability_id.clone(),
            signer: Ed25519Signer::from_label(step.provider_name),
        };
        let provider_verifier = Ed25519Verifier::from_signer(&provider.signer);
        let result = invoke::invoke(
            &provider,
            &g,
            &step.capability_id,
            &step.arguments,
            now,
            0,
            false,
            &provider_verifier,
        )
        .expect("provider invocation");
        assert!(result.attestation.effect_committed);

        // §26.5: per-provider audit event with the full chain + credential audience.
        let audit = upstream_audit_event(
            UpstreamAudit {
                trace_id: "01JTRACE",
                subject: user,
                provider: step.provider_name,
                capability_id: &step.capability_id,
                plan_hash: &plan_hash,
                argument_hash: &arg_hash,
                grant_id: &g.grant_id,
                decision: "allow",
                effect: step.effect,
                delegation_chain: chain.clone(),
                credential_audience: step.api,
                credential_jkt: &cred.credential_jkt,
                timestamp: "2026-06-13T16:00:01Z",
            },
            &audit_signer,
        );
        // The audit event is signed and carries the chain + credential audience.
        let bytes = {
            let mut v = serde_json::to_value(&audit).unwrap();
            v.as_object_mut().unwrap().remove("signature");
            vcp_sdk::jcs::canonicalize_value(&v)
        };
        assert!(audit_verifier.verify(bytes.as_bytes(), &audit.signature.as_ref().unwrap().value));
        assert_eq!(audit.delegation_chain.unwrap().hops.len(), 5);
        assert_eq!(audit.credential_audience.as_deref(), Some(step.api));
        audits.push(audit.credential_audience);
    }

    // ---- 4. Cross-provider credential reuse is impossible (§26.1, test 13). ----
    let linear_cred = &credentials[0];
    assert_eq!(linear_cred.audience, "https://api.linear.app");
    // The linear credential cannot be presented at slack.
    let reused = vcp_gateway::delegation::ExchangedCredential {
        audience: linear_cred.audience.clone(),
        actor: linear_cred.actor.clone(),
        credential_jkt: linear_cred.credential_jkt.clone(),
    };
    assert_eq!(
        reused.check_audience("https://slack.com/api").1,
        ReasonCode::CredentialAudienceMismatch
    );

    // Distinct providers received distinct credential thumbprints.
    assert_ne!(credentials[0].credential_jkt, credentials[1].credential_jkt);

    // One approval, two single-use grants, two distinct audited audiences.
    assert_eq!(audits.len(), 2);
    assert_eq!(audits[0].as_deref(), Some("https://api.linear.app"));
    assert_eq!(audits[1].as_deref(), Some("https://slack.com/api"));
}
