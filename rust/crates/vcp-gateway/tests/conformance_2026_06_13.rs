//! Conformance vectors for the 2026-06-13 additions:
//!
//! - `reason-codes.json` (§23): every registry code present, with the right
//!   category.
//! - `task-rules.json` (§21): task lifecycle verdicts (subject scope, expiry,
//!   cancel-revokes-grant).
//! - `delegation.json` (§26): OBO chain construction, per-provider credential
//!   binding, and attenuation (narrow-ok / widen-rejected).
//!
//! Vector paths resolve via `CARGO_MANIFEST_DIR` so the test runs from any cwd.

use serde_json::Value;
use std::path::PathBuf;

use vcp_gateway::delegation::{
    self, DelegationChain, DelegationHop, ExchangedCredential, MockTokenExchangeBroker,
    TokenExchangeBroker,
};
use vcp_gateway::grant::Decision;
use vcp_gateway::reason::{Category, ReasonCode};
use vcp_gateway::task::{Task, TaskManager, TaskOp};

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

// ----------------------------------------------------------------------------
// §23 — reason-code registry
// ----------------------------------------------------------------------------

#[test]
fn reason_codes_vector() {
    let v = load("reason-codes.json");
    let codes = v["codes"].as_array().unwrap();

    // Every code in the vector MUST be present in the enum with the right
    // category.
    for entry in codes {
        let code_str = entry["code"].as_str().unwrap();
        let category_str = entry["category"].as_str().unwrap();
        let remediable = entry["remediable"].as_bool().unwrap();

        let code = ReasonCode::from_str(code_str)
            .unwrap_or_else(|| panic!("reason code {code_str} missing from registry enum"));

        let want_category = match category_str {
            "allow" => Category::Allow,
            "challenge" => Category::Challenge,
            "deny" => Category::Deny,
            other => panic!("unknown category {other}"),
        };
        assert_eq!(
            code.category(),
            want_category,
            "category mismatch for {code_str}"
        );
        assert_eq!(
            code.category().as_str(),
            category_str,
            "category string mismatch for {code_str}"
        );
        assert_eq!(
            code.remediable(),
            remediable,
            "remediable mismatch for {code_str}"
        );
    }

    // ...and the enum carries no extra codes the registry does not (exact 1:1).
    assert_eq!(
        ReasonCode::ALL.len(),
        codes.len(),
        "enum has a different number of codes than the registry"
    );
}

// ----------------------------------------------------------------------------
// §21 — task lifecycle
// ----------------------------------------------------------------------------

#[test]
fn task_rules_vector() {
    let v = load("task-rules.json");
    let task: Task = serde_json::from_value(v["task"].clone()).expect("task parses");

    let mut mgr = TaskManager::new();
    mgr.create(task.clone());

    for op_case in v["operations"].as_array().unwrap() {
        let name = op_case["name"].as_str().unwrap();
        let op = TaskOp::from_str(op_case["op"].as_str().unwrap()).expect("known op");
        let subject = op_case["subject"].as_str().unwrap();
        let now = vcp_gateway::grant::parse_rfc3339(op_case["now"].as_str().unwrap())
            .expect("now parses");
        let cancelled = op_case["cancelled"].as_bool().unwrap();

        let verdict = mgr.evaluate(&task, subject, now, cancelled, op);

        let expect = &op_case["expect"];
        let want_decision = expect["decision"].as_str().unwrap();
        let want_reason = expect["reason_code"].as_str().unwrap();

        assert_eq!(
            decision_str(&verdict.decision),
            want_decision,
            "decision mismatch in {name}"
        );
        assert_eq!(
            verdict.reason_code.as_str(),
            want_reason,
            "reason_code mismatch in {name}"
        );
    }
}

#[test]
fn task_cancel_revokes_grant() {
    // A live manager: cancelling the task revokes its grant so a later invoke is
    // denied with GRANT_REVOKED, while a get/cancel by the owner before expiry is
    // fine (§21).
    let v = load("task-rules.json");
    let task: Task = serde_json::from_value(v["task"].clone()).expect("task parses");
    let mut mgr = TaskManager::new();
    mgr.create(task.clone());

    let now = vcp_gateway::grant::parse_rfc3339("2026-06-13T16:05:00Z").unwrap();

    // Cancel by the owner.
    let cancel = mgr.cancel(&task.task_id, "user:123", now);
    assert_eq!(cancel.decision, Decision::Allow);
    assert!(mgr.is_cancelled(&task.task_id));

    // An invoke after cancel is denied GRANT_REVOKED (using tracked state).
    let verdict = mgr.evaluate(
        mgr.get(&task.task_id).unwrap(),
        "user:123",
        now,
        mgr.is_cancelled(&task.task_id),
        TaskOp::Invoke,
    );
    assert_eq!(verdict.reason_code, ReasonCode::GrantRevoked);
}

// ----------------------------------------------------------------------------
// §26 — multi-provider OBO delegation
// ----------------------------------------------------------------------------

#[test]
fn delegation_chain_cases() {
    let v = load("delegation.json");
    for case in v["chain_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let chain = DelegationChain::build(
            case["user"].as_str().unwrap(),
            case["agent"].as_str().unwrap(),
            case["gateway"].as_str().unwrap(),
            case["provider"].as_str().unwrap(),
            case["api"].as_str().unwrap(),
        );

        let want: Vec<DelegationHop> = case["expect_chain"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| DelegationHop {
                role: h["role"].as_str().unwrap().to_string(),
                id: h["id"].as_str().unwrap().to_string(),
            })
            .collect();

        assert_eq!(chain.hops, want, "chain mismatch in {name}");
    }
}

#[test]
fn delegation_credential_cases() {
    let v = load("delegation.json");
    for case in v["credential_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let expect = &case["expect"];
        let want_decision = expect["decision"].as_str().unwrap();
        let want_reason = expect["reason_code"].as_str().unwrap();

        // Two flavors of audience case: an exchanged credential bound to an API,
        // and a grant bound to a capability.
        let (decision, reason) = if let Some(cred_aud) = case.get("credential_audience") {
            let presented_at = case["presented_at"].as_str().unwrap();
            // Mint via the broker so the test exercises the real exchange path.
            let broker = MockTokenExchangeBroker;
            let cred = broker.exchange("user:123", "agent:triage", cred_aud.as_str().unwrap());
            // The actor claim names the agent acting for the user (§26.1).
            assert_eq!(cred.actor.sub, "agent:triage");
            assert_eq!(cred.actor.on_behalf_of, "user:123");
            cred.check_audience(presented_at)
        } else {
            let grant_aud = case["grant_audience"].as_str().unwrap();
            let capability = case["capability"].as_str().unwrap();
            delegation::check_grant_audience(grant_aud, capability)
        };

        assert_eq!(
            decision_str(&decision),
            want_decision,
            "decision mismatch in {name}"
        );
        assert_eq!(reason.as_str(), want_reason, "reason mismatch in {name}");
    }
}

#[test]
fn delegation_attenuation_cases() {
    let v = load("delegation.json");
    for case in v["attenuation_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let parent: Vec<String> = case["parent_scope"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect();
        let child: Vec<String> = case["child_scope"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect();

        let (decision, reason) = delegation::check_attenuation(&parent, &child);

        let expect = &case["expect"];
        let want_decision = expect["decision"].as_str().unwrap();
        assert_eq!(
            decision_str(&decision),
            want_decision,
            "decision mismatch in {name}"
        );
        // reason_code is only asserted where the vector supplies one (deny cases).
        if let Some(want_reason) = expect.get("reason_code").and_then(|r| r.as_str()) {
            assert_eq!(reason.as_str(), want_reason, "reason mismatch in {name}");
        }
    }
}

#[test]
fn distinct_providers_get_distinct_credentials() {
    // §26.1: a credential minted for Provider A is unusable at Provider B, and
    // distinct providers receive distinct credential thumbprints.
    let broker = MockTokenExchangeBroker;
    let linear: ExchangedCredential =
        broker.exchange("user:123", "agent:triage", "https://api.linear.app");
    let slack: ExchangedCredential =
        broker.exchange("user:123", "agent:triage", "https://slack.com/api");

    assert_ne!(linear.credential_jkt, slack.credential_jkt);
    // linear credential rejected at slack.
    assert_eq!(
        linear.check_audience("https://slack.com/api").1,
        ReasonCode::CredentialAudienceMismatch
    );
    // ...and accepted at linear.
    assert_eq!(
        linear.check_audience("https://api.linear.app").1,
        ReasonCode::Ok
    );
}
