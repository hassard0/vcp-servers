//! Manifest types (VCP §5.2) and the contract partition (§4).
//!
//! The `Contract` is the security-relevant subset that defines identity. The
//! `Manifest` wraps a contract with display strings, provenance, and a
//! signature, none of which affect identity.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::identity;

/// Effect class (§11).
pub type EffectClass = String;
/// Determinism class (§10).
pub type DeterminismClass = String;

/// Declared effects of a capability (§11).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Effects {
    pub class: EffectClass,
    pub external_side_effect: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub requires_user_approval: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub compensating_action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub may_send_to: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub may_read_from: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub may_write_to: Option<Vec<String>>,
}

/// Declared determinism semantics (§10).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Determinism {
    pub class: DeterminismClass,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub requires_idempotency_key: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub supports_dry_run: Option<bool>,
}

/// Sandbox allowlists (§14).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Sandbox {
    /// `"none"` or an array of path/glob strings. Kept as a raw `Value` so the
    /// `oneOf` in the schema round-trips and canonicalizes identically.
    pub filesystem: Value,
    pub network: Vec<String>,
    pub secrets: Vec<String>,
}

/// The contract: the security-relevant subset of a manifest that defines
/// identity (§4). Field set and ordering match the conformance contract; JCS
/// sorts keys at hash time, so declaration order here is irrelevant to the hash.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Contract {
    pub issuer: String,
    pub name: String,
    pub version: String,
    pub input_schema: Value,
    pub output_schema: Value,
    pub effects: Effects,
    pub determinism: Determinism,
    pub sandbox: Sandbox,
}

impl Contract {
    /// `contract_hash = sha256(JCS(contract))` (§4).
    pub fn contract_hash(&self) -> String {
        // serialize to Value, then JCS — guarantees the same bytes a verifier
        // computes from the wire form.
        let v = serde_json::to_value(self).expect("contract serializes");
        identity::contract_hash_value(&v)
    }

    /// `capability_id = vcp:cap:<name>@<contract_hash>` (§4).
    pub fn capability_id(&self) -> String {
        identity::capability_id(&self.name, &self.contract_hash())
    }
}

/// In-band signature block (§3). Default algorithm Ed25519.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Signature {
    pub alg: String,
    pub value: String,
}

/// The capability body of a manifest (§5.2). Carries the contract fields plus
/// the display strings and content-addressed id.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Capability {
    pub id: String,
    pub name: String,
    pub version: String,
    pub contract_hash: String,
    pub summary_for_user: String,
    pub summary_for_model: String,
    pub input_schema: Value,
    pub output_schema: Value,
    pub effects: Effects,
    pub determinism: Determinism,
    pub sandbox: Sandbox,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub kind: Option<String>,
}

impl Capability {
    /// Reconstruct the identity-defining contract from this capability body.
    pub fn contract(&self, issuer: &str) -> Contract {
        Contract {
            issuer: issuer.to_string(),
            name: self.name.clone(),
            version: self.version.clone(),
            input_schema: self.input_schema.clone(),
            output_schema: self.output_schema.clone(),
            effects: self.effects.clone(),
            determinism: self.determinism.clone(),
            sandbox: self.sandbox.clone(),
        }
    }
}

/// A signed capability manifest (§5.2).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Manifest {
    pub vcp: String,
    pub kind: String,
    pub issuer: String,
    pub provider: String,
    pub capability: Capability,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub provenance: Option<Value>,
    pub signature: Signature,
}

impl Manifest {
    /// The contract for this manifest (the identity-defining subset, §4).
    pub fn contract(&self) -> Contract {
        self.capability.contract(&self.issuer)
    }

    /// The JCS bytes over which the signature is computed: the whole manifest
    /// with the `signature` block removed (§3 rule 4).
    pub fn signing_bytes(&self) -> String {
        let mut v = serde_json::to_value(self).expect("manifest serializes");
        if let Value::Object(ref mut map) = v {
            map.remove("signature");
        }
        crate::jcs::canonicalize_value(&v)
    }
}
