//! MCP bridge profile (`VCP-Bridge`, §16).
//!
//! Wraps a legacy MCP tool as a VCP capability. The two load-bearing rules:
//!
//! 1. **Never pass raw MCP text as instruction.** The upstream tool description
//!    is treated as untrusted Provider metadata. We pin its hash and synthesize
//!    a Gateway-compiled affordance for the model instead of forwarding the raw
//!    string (tool-poisoning defense, §13 / §18 test 1).
//! 2. **Pin the observed schema+description hash.** If the upstream MCP server
//!    later changes either, the pinned hash no longer matches and the bridge
//!    treats it as a new, unapproved capability (rug-pull defense, §4 / §18
//!    test 2).
//!
//! Provenance is marked `legacy_mcp`; a bridged capability is at most VCP-L0.

use serde_json::{json, Value};

use crate::identity;
use crate::jcs;
use crate::manifest::{Capability, Determinism, Effects, Manifest, Sandbox, Signature};
use crate::signer::Signer;

/// An observed MCP tool as advertised by an upstream server.
pub struct McpTool {
    pub name: String,
    /// Raw natural-language description. UNTRUSTED — never forwarded verbatim.
    pub description: String,
    pub input_schema: Value,
}

/// The result of bridging an MCP tool: a VCP manifest plus the pinned hash of
/// the observed (schema + description) so later drift is detectable.
pub struct BridgedCapability {
    pub manifest: Manifest,
    /// `sha256:` over the observed `{description, input_schema}` (the rug-pull
    /// pin). Recompute on every refresh; a mismatch means a new capability.
    pub observed_hash: String,
}

/// Compute the pinned observation hash for an MCP tool (§16: pin schema +
/// description). Bound over the raw, untrusted upstream surface so any change
/// produces a different pin.
pub fn observed_hash(tool: &McpTool) -> String {
    jcs::hash_value(&json!({
        "description": tool.description,
        "input_schema": tool.input_schema,
    }))
}

/// Bridge a legacy MCP tool into a signed VCP manifest (§16).
///
/// `provider` is the bridge's namespace (e.g. `legacy.filesystem`). The bridge
/// signs the manifest with its own key; provenance is `legacy_mcp`. The model
/// summary is Gateway-compiled and does NOT echo the raw MCP description.
pub fn bridge_mcp_tool(provider: &str, tool: &McpTool, signer: &dyn Signer) -> BridgedCapability {
    let observed = observed_hash(tool);

    // A bridged MCP tool is opaque: we cannot know its true effects, so it is
    // conservatively classed as an external side-effecting write requiring
    // approval. Sandbox is deny-all by default (the bridge adds policy + audit,
    // not real isolation, hence VCP-L0).
    let effects = Effects {
        class: "write-irreversible".to_string(),
        external_side_effect: true,
        requires_user_approval: Some(true),
        compensating_action: None,
        may_send_to: None,
        may_read_from: None,
        may_write_to: None,
    };
    let determinism = Determinism {
        class: "nondeterministic".to_string(),
        requires_idempotency_key: Some(false),
        supports_dry_run: Some(false),
    };
    let sandbox = Sandbox {
        filesystem: json!("none"),
        network: vec![],
        secrets: vec![],
    };

    let issuer = format!("bridge:{provider}");
    let contract = json!({
        "issuer": issuer,
        "name": tool.name,
        "version": "legacy",
        "input_schema": tool.input_schema,
        "output_schema": { "type": "object" },
        "effects": effects,
        "determinism": determinism,
        "sandbox": sandbox,
    });
    let contract_hash = identity::contract_hash_value(&contract);
    let cap_id = identity::capability_id(&tool.name, &contract_hash);

    // Gateway-compiled affordance: a neutral description of WHAT the capability
    // is, derived from structure, NOT the raw upstream prose. The raw text is
    // never surfaced to the Planner.
    let summary_for_model = format!(
        "Bridged legacy MCP tool '{}'. Effects are unverified (provenance legacy_mcp); \
         every write requires policy approval. Arguments must match the pinned schema.",
        tool.name
    );
    let summary_for_user = format!(
        "Legacy MCP tool '{}' (bridged, unverified). Pinned observation {}.",
        tool.name, observed
    );

    let capability = Capability {
        id: cap_id,
        name: tool.name.clone(),
        version: "legacy".to_string(),
        contract_hash,
        summary_for_user,
        summary_for_model,
        input_schema: tool.input_schema.clone(),
        output_schema: json!({ "type": "object" }),
        effects,
        determinism,
        sandbox,
        kind: Some("tool".to_string()),
    };

    let mut manifest = Manifest {
        vcp: "0.1".to_string(),
        kind: "capability.manifest".to_string(),
        issuer,
        provider: provider.to_string(),
        capability,
        provenance: Some(json!({
            "provenance": "legacy_mcp",
            "observed_hash": observed,
        })),
        signature: Signature {
            alg: signer.alg().to_string(),
            value: String::new(),
        },
    };

    let sig_value = signer.sign(manifest.signing_bytes().as_bytes());
    manifest.signature.value = sig_value;

    BridgedCapability {
        manifest,
        observed_hash: observed,
    }
}
