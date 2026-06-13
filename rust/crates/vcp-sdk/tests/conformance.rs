//! Conformance vectors the SDK MUST reproduce (vcp-servers/conformance):
//! canonical-hash.json (§3), capability-identity.json (§4), argument-binding.json
//! (§7/§8). Vector paths resolve via CARGO_MANIFEST_DIR so the test runs from
//! any cwd.

use serde_json::Value;
use std::path::PathBuf;

use vcp_sdk::identity;
use vcp_sdk::jcs;

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
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_slice(&bytes).expect("vector is valid JSON")
}

#[test]
fn canonical_hash_vector() {
    let v = load("canonical-hash.json");
    for case in v["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let value = &case["value"];
        let expected_canonical = case["canonical"].as_str().unwrap();
        let expected_sha = case["sha256"].as_str().unwrap();

        let canonical = jcs::canonicalize_value(value);
        assert_eq!(canonical, expected_canonical, "canonical mismatch in {name}");

        let sha = jcs::hash_value(value);
        assert_eq!(sha, expected_sha, "sha256 mismatch in {name}");
    }
}

#[test]
fn capability_identity_vector() {
    let v = load("capability-identity.json");

    let contract = &v["contract"];
    let expected_hash = v["contract_hash"].as_str().unwrap();
    let expected_id = v["capability_id"].as_str().unwrap();

    let name = contract["name"].as_str().unwrap();
    let (ch, id) = identity::identity_for(name, contract);
    assert_eq!(ch, expected_hash, "contract_hash mismatch");
    assert_eq!(id, expected_id, "capability_id mismatch");

    // Mutated contract MUST yield a different identity (rug-pull -> new identity).
    let mutated = &v["mutated_network"]["contract"];
    let expected_mut_hash = v["mutated_network"]["contract_hash"].as_str().unwrap();
    let mut_hash = identity::contract_hash_value(mutated);
    assert_eq!(mut_hash, expected_mut_hash, "mutated contract_hash mismatch");
    assert_ne!(mut_hash, ch, "mutation MUST change identity");
}

#[test]
fn argument_binding_vector() {
    let v = load("argument-binding.json");

    let args = &v["arguments"];
    let expected = v["argument_hash"].as_str().unwrap();
    assert_eq!(identity::argument_hash_value(args), expected, "argument_hash mismatch");

    let tampered = &v["tampered_arguments"];
    let expected_tampered = v["tampered_argument_hash"].as_str().unwrap();
    let tampered_hash = identity::argument_hash_value(tampered);
    assert_eq!(tampered_hash, expected_tampered, "tampered hash mismatch");
    assert_ne!(tampered_hash, expected, "tampering MUST change the hash");
}
