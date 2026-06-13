//! Plans (§9). The Planner proposes; it has no authority. The Gateway computes
//! `plan_hash = sha256(JCS(plan))` and binds approval and grants to it.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::jcs;

/// A declared data input with its taint label (§12), feeding the §6 `data_flows`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DataRef {
    pub source: String,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub classification: Option<String>,
}

/// One proposed capability invocation (§9).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PlanStep {
    pub id: String,
    pub capability: String,
    pub arguments: Value,
    pub effect: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub depends_on: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub consumes: Option<Vec<DataRef>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub why: Option<String>,
}

/// An ordered set of proposed invocations (§9).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Plan {
    pub kind: String,
    pub steps: Vec<PlanStep>,
}

impl Plan {
    /// `plan_hash = sha256(JCS(plan))` (§9).
    pub fn plan_hash(&self) -> String {
        let v = serde_json::to_value(self).expect("plan serializes");
        jcs::hash_value(&v)
    }
}

/// A proposed plan together with its computed hash.
#[derive(Debug, Clone)]
pub struct ProposedPlan {
    pub plan: Plan,
    pub plan_hash: String,
}

/// Build a plan from steps and compute its hash (the Planner-side helper). The
/// Gateway independently recomputes the hash before binding authority to it.
pub fn propose_plan(steps: Vec<PlanStep>) -> ProposedPlan {
    let plan = Plan {
        kind: "vcp.plan".to_string(),
        steps,
    };
    let plan_hash = plan.plan_hash();
    ProposedPlan { plan, plan_hash }
}
