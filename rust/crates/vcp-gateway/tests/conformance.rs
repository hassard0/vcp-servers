//! Conformance vectors the Gateway MUST reproduce: grant-rules.json (§7) and
//! taint.json (§12). Plus the end-to-end §16 calendar scenario.

use serde_json::Value;
use std::path::PathBuf;

use vcp_gateway::grant::{self, Attempt, Decision, Grant};
use vcp_gateway::taint;

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
    let bytes =
        std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_slice(&bytes).expect("vector is valid JSON")
}

#[test]
fn grant_rules_vector() {
    let v = load("grant-rules.json");
    let grant: Grant = serde_json::from_value(v["grant"].clone()).expect("grant parses");
    let default_now = v["now"].as_str().unwrap();

    for attempt in v["attempts"].as_array().unwrap() {
        let name = attempt["name"].as_str().unwrap();
        let capability = attempt["capability"].as_str().unwrap().to_string();
        let argument_hash = attempt["argument_hash"].as_str().unwrap().to_string();
        let call_index = attempt["call_index"].as_u64().unwrap();
        // Per-attempt `now` override (the expired case sets its own).
        let now_str = attempt
            .get("now")
            .and_then(|n| n.as_str())
            .unwrap_or(default_now);
        let now = grant::parse_rfc3339(now_str).expect("now parses");

        let a = Attempt {
            capability,
            argument_hash,
        };
        let (decision, reason) = grant::verify_grant(&grant, &a, now, call_index);

        let expect = &attempt["expect"];
        let want_decision = expect["decision"].as_str().unwrap();
        let want_reason = expect["reason_code"].as_str().unwrap();

        let got_decision = match decision {
            Decision::Allow => "allow",
            Decision::Deny => "deny",
        };
        assert_eq!(got_decision, want_decision, "decision mismatch in {name}");
        assert_eq!(reason, want_reason, "reason_code mismatch in {name}");
    }
}

#[test]
fn taint_propagation_vector() {
    let v = load("taint.json");

    // The lattice order must match the vector exactly.
    let order: Vec<&str> = v["restrictiveness_order_most_to_least"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap())
        .collect();
    assert_eq!(
        order,
        taint::RESTRICTIVENESS_MOST_TO_LEAST.to_vec(),
        "lattice order mismatch"
    );

    for case in v["propagation_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let sources: Vec<&str> = case["sources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap())
            .collect();
        let expect = case["expect_label"].as_str().unwrap();
        let got = taint::propagate(&sources).unwrap();
        assert_eq!(got, expect, "propagation mismatch in {name}");
    }
}

#[test]
fn taint_authority_vector() {
    let v = load("taint.json");
    for case in v["authority_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let label = case["label"].as_str().unwrap();
        let authorizes = case["authorizes"].as_bool().unwrap();
        let expect = &case["expect"];
        let want_decision = expect["decision"].as_str().unwrap();

        let decision = taint::check_authority(label, authorizes);
        match (&decision, want_decision) {
            (taint::TaintDecision::Allow, "allow") => {}
            (taint::TaintDecision::Deny(code), "deny") => {
                let want_reason = expect["reason_code"].as_str().unwrap();
                assert_eq!(*code, want_reason, "reason_code mismatch in {name}");
            }
            other => panic!("authority decision mismatch in {name}: {other:?} vs {want_decision}"),
        }
    }
}

#[test]
fn taint_dataflow_vector() {
    let v = load("taint.json");
    for case in v["dataflow_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let flow = taint::DataFlow {
            from: case["from"].as_str().unwrap(),
            to: case["to"].as_str().unwrap(),
            classification: case["classification"].as_str().unwrap(),
            sink: case["sink"].as_str().unwrap(),
        };
        let expect = &case["expect"];
        let want_decision = expect["decision"].as_str().unwrap();
        let decision = taint::check_data_flow(&flow);
        match (&decision, want_decision) {
            (taint::TaintDecision::Allow, "allow") => {}
            (taint::TaintDecision::Deny(code), "deny") => {
                let want_reason = expect["reason_code"].as_str().unwrap();
                assert_eq!(*code, want_reason, "reason_code mismatch in {name}");
            }
            other => panic!("dataflow decision mismatch in {name}: {other:?} vs {want_decision}"),
        }
    }
}
