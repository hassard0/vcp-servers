//! Interface capabilities: signed, sandboxed UI (§22).
//!
//! An `interface` capability ships an interactive surface (dashboard, form,
//! chart, picker). The model never sees the UI's code as instruction; the user
//! sees a rendered, sandboxed surface; and any action the UI takes is an ordinary
//! VCP capability call subject to policy and grants.
//!
//! This module enforces the two load-bearing §22 rules and reproduces security
//! test 18:
//!
//! - the UI artifact is **content-addressed**: the Host MUST verify `content_hash`
//!   against the bytes it renders and reject a mismatch (`INTERFACE_HASH_MISMATCH`).
//! - **every action a UI initiates is a capability call**; a UI MUST NOT invoke a
//!   capability that is not in its declared `host_actions` allowlist.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::grant::Decision;
use crate::reason::ReasonCode;

/// The content-addressed `interface` block declared in a manifest (§22).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InterfaceBlock {
    /// The content-addressed UI surface identifier, e.g.
    /// `vcp:ui:example.calendar.picker@sha256:7d21...`.
    pub surface: String,
    /// `sha256:` of the canonical UI artifact bytes (§22).
    pub content_hash: String,
    /// Render mode, e.g. `"html-sandboxed"`.
    pub render: String,
    /// Content-Security-Policy directives the Host MUST enforce; absent ⇒
    /// deny-all default (§22).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub csp: Option<BTreeMap<String, Vec<String>>>,
    #[serde(default)]
    pub permissions: Vec<String>,
    /// The capability ids this UI is allowed to invoke through the Gateway (§22).
    #[serde(default)]
    pub host_actions: Vec<String>,
    #[serde(default)]
    pub model_visible: bool,
}

/// Why an interface artifact or action was rejected (§22).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterfaceError {
    /// Rendered bytes differ from `content_hash` (test 18).
    HashMismatch,
    /// A UI-initiated action targets a capability not in `host_actions`.
    ActionNotAllowed,
}

impl InterfaceError {
    /// The registry reason code for this error (§23).
    pub fn reason_code(&self) -> ReasonCode {
        match self {
            InterfaceError::HashMismatch => ReasonCode::InterfaceHashMismatch,
            // A UI escalating beyond its host capability is an audience violation:
            // the action is addressed to a capability the UI was not granted.
            InterfaceError::ActionNotAllowed => ReasonCode::AudienceMismatch,
        }
    }
}

impl InterfaceBlock {
    /// Verify the artifact bytes the Host is about to render against the declared
    /// `content_hash` (§22, test 18). A changed UI is a new identity, exactly like
    /// a changed contract (§4); a mismatch MUST be rejected.
    pub fn verify_artifact(&self, artifact_bytes: &[u8]) -> Result<(), InterfaceError> {
        let computed = vcp_sdk::jcs::hash_bytes(artifact_bytes);
        // Exact, byte-for-byte comparison of the content address (§3).
        if computed == self.content_hash {
            Ok(())
        } else {
            Err(InterfaceError::HashMismatch)
        }
    }

    /// Enforce the `host_actions` allowlist (§22): a UI MUST NOT invoke a
    /// capability that is not declared. Comparison is exact, byte-for-byte (§3).
    pub fn authorize_action(&self, capability_id: &str) -> Result<(), InterfaceError> {
        if self.host_actions.iter().any(|a| a == capability_id) {
            Ok(())
        } else {
            Err(InterfaceError::ActionNotAllowed)
        }
    }

    /// Combined verdict helper: verify the artifact, then authorize the action.
    /// Returns `(Decision, ReasonCode)` for audit-friendly call sites.
    pub fn check(
        &self,
        artifact_bytes: &[u8],
        capability_id: &str,
    ) -> (Decision, ReasonCode) {
        match self
            .verify_artifact(artifact_bytes)
            .and_then(|()| self.authorize_action(capability_id))
        {
            Ok(()) => (Decision::Allow, ReasonCode::Ok),
            Err(e) => (Decision::Deny, e.reason_code()),
        }
    }
}
