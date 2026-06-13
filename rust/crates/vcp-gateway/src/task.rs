//! Asynchronous execution: Tasks (§21).
//!
//! A `task` is the grant-safe "call-now, fetch-later" pattern. A task handle is a
//! `state` handle (§5.1): typed, expiring, and scoped to the subject that created
//! it. The originating **grant governs the whole task lifetime** and **cancel
//! revokes the grant**.
//!
//! [`TaskManager`] reproduces every verdict in
//! `conformance/vectors/task-rules.json`:
//!
//! - `tasks/get|cancel|invoke` from a different subject ⇒ `SUBJECT_MISMATCH` (§21).
//! - any operation at or after `expires_at` ⇒ `TASK_EXPIRED` (§21, test 15).
//! - `invoke` under a cancelled task ⇒ `GRANT_REVOKED` (§21, test 16).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::grant::{parse_rfc3339, Decision};
use crate::reason::ReasonCode;

/// A long-running, grant-bound asynchronous execution handle (§21).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Task {
    pub kind: String,
    pub task_id: String,
    pub capability_id: String,
    pub grant_id: String,
    /// The subject that created the task; only this subject may operate it (§21).
    pub subject: String,
    pub status: String,
    pub created_at: String,
    pub expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub progress: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub result_ref: Option<String>,
}

/// The operations a Host/Planner can request against a task (§21). They are
/// stateless requests; there is no implicit task session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskOp {
    Get,
    Cancel,
    Update,
    /// Commit a further effect under the task's grant.
    Invoke,
}

impl TaskOp {
    /// Parse the `op` string used in `task-rules.json`.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<TaskOp> {
        match s {
            "get" => Some(TaskOp::Get),
            "cancel" => Some(TaskOp::Cancel),
            "update" => Some(TaskOp::Update),
            "invoke" => Some(TaskOp::Invoke),
            _ => None,
        }
    }
}

/// Holds tasks and tracks per-task cancellation (cancel ⇒ grant revoked, §21).
#[derive(Default)]
pub struct TaskManager {
    tasks: HashMap<String, Task>,
    /// task_id ⇒ whether `tasks/cancel` has been called (grant revoked).
    cancelled: HashMap<String, bool>,
}

impl TaskManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a created task. `max_calls` accounting is charged once, at task
    /// creation (§21), by the caller before this point.
    pub fn create(&mut self, task: Task) {
        self.cancelled.insert(task.task_id.clone(), false);
        self.tasks.insert(task.task_id.clone(), task);
    }

    /// Look up a task by id.
    pub fn get(&self, task_id: &str) -> Option<&Task> {
        self.tasks.get(task_id)
    }

    /// Whether the task's grant has been revoked by cancellation (§21).
    pub fn is_cancelled(&self, task_id: &str) -> bool {
        self.cancelled.get(task_id).copied().unwrap_or(false)
    }

    /// Mark a task cancelled: this **revokes its grant** so no further effect can
    /// be committed under it (§21). Returns the would-be audit decision.
    pub fn cancel(&mut self, task_id: &str, subject: &str, now: OffsetDateTime) -> TaskVerdict {
        // A cancel is still subject- and expiry-scoped.
        let pre = self.authorize(task_id, subject, now, false, TaskOp::Cancel);
        if pre.decision == Decision::Allow {
            self.cancelled.insert(task_id.to_string(), true);
            if let Some(t) = self.tasks.get_mut(task_id) {
                t.status = "cancelled".to_string();
            }
        }
        pre
    }

    /// Authorize an operation against a task at logical time `now`. `cancelled`
    /// may be supplied directly (the vector toggles it) or, when `None`, read from
    /// this manager's tracked state.
    ///
    /// Check order is fail-closed and matches the spec narrative: ownership
    /// (subject), then expiry, then — for an effect-committing `invoke` — whether
    /// the grant was revoked by cancellation.
    pub fn evaluate(
        &self,
        task: &Task,
        subject: &str,
        now: OffsetDateTime,
        cancelled: bool,
        op: TaskOp,
    ) -> TaskVerdict {
        // Subject-scoped (§21): reject any operation by a non-owning subject.
        if subject != task.subject {
            return TaskVerdict::deny(ReasonCode::SubjectMismatch);
        }

        // Expiring handle (§21, test 15): reject at or after expiry. A Gateway
        // MUST NOT let a task outlive its grant's expires_at.
        match parse_rfc3339(&task.expires_at) {
            Some(exp) if now >= exp => return TaskVerdict::deny(ReasonCode::TaskExpired),
            None => return TaskVerdict::deny(ReasonCode::TaskExpired), // unparseable ⇒ fail closed
            _ => {}
        }

        // Cancel revokes the grant (§21, test 16): an effect-committing invoke
        // under a cancelled task is denied with GRANT_REVOKED.
        if op == TaskOp::Invoke && cancelled {
            return TaskVerdict::deny(ReasonCode::GrantRevoked);
        }

        TaskVerdict::allow()
    }

    /// Authorize using the manager's own stored task + cancellation state.
    fn authorize(
        &self,
        task_id: &str,
        subject: &str,
        now: OffsetDateTime,
        cancelled_override: bool,
        op: TaskOp,
    ) -> TaskVerdict {
        match self.tasks.get(task_id) {
            Some(t) => {
                let cancelled = cancelled_override || self.is_cancelled(task_id);
                self.evaluate(t, subject, now, cancelled, op)
            }
            None => TaskVerdict::deny(ReasonCode::SubjectMismatch),
        }
    }
}

/// Allow/deny verdict for a task operation, carrying a registry reason code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskVerdict {
    pub decision: Decision,
    pub reason_code: ReasonCode,
}

impl TaskVerdict {
    pub fn allow() -> Self {
        Self {
            decision: Decision::Allow,
            reason_code: ReasonCode::Ok,
        }
    }
    pub fn deny(code: ReasonCode) -> Self {
        Self {
            decision: Decision::Deny,
            reason_code: code,
        }
    }
}
