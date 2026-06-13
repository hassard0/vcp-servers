//! Taint / data-flow engine (§12).
//!
//! Reproduces `conformance/vectors/taint.json`:
//!
//! - **Most-restrictive propagation:** derived data inherits the most
//!   restrictive label among its sources.
//! - **Authority rule:** authority derived from an `untrusted_*` label is
//!   denied (`AUTHORITY_FROM_TAINTED_DATA`).
//! - **Data-flow rule:** moving classified data to an external sink is forbidden
//!   (`DATA_FLOW_FORBIDDEN`); the same data may flow into internal capability
//!   *metadata*.

/// The eight taint labels (§12), ordered most-restrictive (index 0) to
/// least-restrictive. This is the lattice ordering the spec and `taint.json`
/// agree on (`restrictiveness_order_most_to_least`).
pub const RESTRICTIVENESS_MOST_TO_LEAST: [&str; 8] = [
    "secret",
    "untrusted_tool_result",
    "untrusted_resource_data",
    "policy_only",
    "trusted_manifest_summary",
    "user_instruction",
    "developer_instruction",
    "system_instruction",
];

/// Rank of a label: 0 = most restrictive. Unknown labels are treated as maximally
/// restrictive (fail closed).
fn rank(label: &str) -> usize {
    RESTRICTIVENESS_MOST_TO_LEAST
        .iter()
        .position(|l| *l == label)
        .unwrap_or(0)
}

/// True if a label denotes untrusted, non-authoritative data (§12).
pub fn is_untrusted(label: &str) -> bool {
    label == "untrusted_resource_data" || label == "untrusted_tool_result"
}

/// Propagate taint: a derived datum inherits the MOST restrictive source label
/// (§12). Returns `None` for an empty source set.
pub fn propagate<'a>(sources: &[&'a str]) -> Option<&'a str> {
    sources.iter().copied().min_by_key(|l| rank(l))
}

/// Decision for an authority check or data-flow check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaintDecision {
    Allow,
    Deny(&'static str),
}

/// Authority rule (§12): a datum with the given label is being used to authorize
/// an action iff `authorizes` is true. Authority from any `untrusted_*` label
/// MUST be denied with `AUTHORITY_FROM_TAINTED_DATA`. Using untrusted data merely
/// as *data* (not authority) is allowed.
pub fn check_authority(label: &str, authorizes: bool) -> TaintDecision {
    if authorizes && is_untrusted(label) {
        TaintDecision::Deny("AUTHORITY_FROM_TAINTED_DATA")
    } else {
        TaintDecision::Allow
    }
}

/// A declared data movement to evaluate (mirrors a `taint.json` dataflow case).
pub struct DataFlow<'a> {
    pub from: &'a str,
    pub to: &'a str,
    pub classification: &'a str,
    /// `"external"` or `"internal-metadata"`.
    pub sink: &'a str,
}

/// Data-flow rule (§12): classified data to an external sink is forbidden
/// (`DATA_FLOW_FORBIDDEN`); the same classified data flowing into internal
/// capability metadata (title/time/attendees) is allowed.
pub fn check_data_flow(flow: &DataFlow) -> TaintDecision {
    let classified = matches!(flow.classification, "confidential" | "personal");
    if classified && flow.sink == "external" {
        TaintDecision::Deny("DATA_FLOW_FORBIDDEN")
    } else {
        TaintDecision::Allow
    }
}
