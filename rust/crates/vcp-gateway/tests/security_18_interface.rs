//! Security test 18 (§18, §22): UI artifact swap.
//!
//! An interface capability ships a content-addressed UI surface. The Host MUST
//! verify the rendered bytes against `content_hash` and reject a mismatch
//! (`INTERFACE_HASH_MISMATCH`). Every action the UI initiates MUST be in its
//! declared `host_actions` allowlist; an action outside it is rejected.

use std::collections::BTreeMap;

use vcp_gateway::grant::Decision;
use vcp_gateway::interface::{InterfaceBlock, InterfaceError};
use vcp_gateway::reason::ReasonCode;

/// The signed UI artifact bytes the provider published.
const UI_ARTIFACT: &[u8] =
    b"<html><body><div id=\"calendar-picker\">pick a slot</div></body></html>";

fn picker_interface() -> InterfaceBlock {
    let content_hash = vcp_sdk::jcs::hash_bytes(UI_ARTIFACT);
    let mut csp = BTreeMap::new();
    csp.insert("default-src".to_string(), vec!["'none'".to_string()]);
    csp.insert(
        "connect-src".to_string(),
        vec!["https://calendar.example.com".to_string()],
    );
    InterfaceBlock {
        surface: format!("vcp:ui:example.calendar.picker@{content_hash}"),
        content_hash,
        render: "html-sandboxed".to_string(),
        csp: Some(csp),
        permissions: vec![],
        host_actions: vec![
            "vcp:cap:calendar.create_event@sha256:9f4c".to_string(),
        ],
        model_visible: false,
    }
}

#[test]
fn interface_hash_match_renders() {
    // The untampered artifact verifies and an allowed action is authorized.
    let iface = picker_interface();
    assert_eq!(iface.verify_artifact(UI_ARTIFACT), Ok(()));

    let (decision, reason) = iface.check(
        UI_ARTIFACT,
        "vcp:cap:calendar.create_event@sha256:9f4c",
    );
    assert_eq!(decision, Decision::Allow);
    assert_eq!(reason, ReasonCode::Ok);
}

#[test]
fn interface_hash_mismatch_rejected() {
    // Test 18: an attacker swaps the UI bytes. content_hash no longer matches ⇒
    // INTERFACE_HASH_MISMATCH.
    let iface = picker_interface();
    let swapped: &[u8] =
        b"<html><body><script>exfiltrate()</script></body></html>";

    assert_eq!(
        iface.verify_artifact(swapped),
        Err(InterfaceError::HashMismatch)
    );

    let (decision, reason) =
        iface.check(swapped, "vcp:cap:calendar.create_event@sha256:9f4c");
    assert_eq!(decision, Decision::Deny);
    assert_eq!(reason, ReasonCode::InterfaceHashMismatch);
}

#[test]
fn interface_action_outside_allowlist_rejected() {
    // A UI MUST NOT invoke a capability not in host_actions (§22). The artifact
    // is genuine, but the action escalates beyond the declared allowlist.
    let iface = picker_interface();
    assert_eq!(
        iface.authorize_action("vcp:cap:slack.post_message@sha256:dead"),
        Err(InterfaceError::ActionNotAllowed)
    );

    let (decision, reason) =
        iface.check(UI_ARTIFACT, "vcp:cap:slack.post_message@sha256:dead");
    assert_eq!(decision, Decision::Deny);
    assert_eq!(reason, ReasonCode::AudienceMismatch);
}
