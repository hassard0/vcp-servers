//! Content-addressed capability identity (VCP §4) and argument binding (§7/§8).
//!
//! `contract_hash = sha256(JCS(contract))`
//! `capability_id = "vcp:cap:" + name + "@" + contract_hash`
//! `argument_hash = sha256(JCS(arguments))`
//!
//! The `contract` is the security-relevant subset of a manifest: `issuer`,
//! `name`, `version`, `input_schema`, `output_schema`, `effects`, `determinism`,
//! `sandbox`. Display strings, signatures, and provenance are excluded so they
//! can change without altering identity. Any change to a contract field yields a
//! new identity (rug-pull becomes a visible diff).

use serde::Serialize;
use serde_json::Value;

use crate::jcs;

/// Compute `contract_hash` = `sha256(JCS(contract))` for an arbitrary contract
/// value (the security-relevant subset of a manifest, already partitioned).
pub fn contract_hash_value(contract: &Value) -> String {
    jcs::hash_value(contract)
}

/// Compute `contract_hash` from any `Serialize` contract type.
pub fn contract_hash<T: Serialize>(contract: &T) -> Result<String, serde_json::Error> {
    jcs::hash(contract)
}

/// Build the content-addressed `capability_id`:
/// `vcp:cap:<name>@<contract_hash>`.
pub fn capability_id(name: &str, contract_hash: &str) -> String {
    format!("vcp:cap:{name}@{contract_hash}")
}

/// Compute both `contract_hash` and `capability_id` from a contract value and
/// its `name`.
pub fn identity_for(name: &str, contract: &Value) -> (String, String) {
    let ch = contract_hash_value(contract);
    let id = capability_id(name, &ch);
    (ch, id)
}

/// `argument_hash = sha256(JCS(arguments))` (§7, §8). A grant binds to this; if
/// the Planner changes any argument the hash no longer matches.
pub fn argument_hash_value(arguments: &Value) -> String {
    jcs::hash_value(arguments)
}

/// Compute `argument_hash` from any `Serialize` arguments type.
pub fn argument_hash<T: Serialize>(arguments: &T) -> Result<String, serde_json::Error> {
    jcs::hash(arguments)
}

/// Extract the `sha256:<hex>` digest embedded in a `vcp:cap:<name>@sha256:<hex>`
/// identifier, if present. Comparison of identifiers elsewhere is exact, byte
/// for byte (§3) — this helper is only for confirming `id` carries the recomputed
/// `contract_hash`.
pub fn digest_of(capability_id: &str) -> Option<&str> {
    capability_id.split_once('@').map(|(_, hash)| hash)
}
