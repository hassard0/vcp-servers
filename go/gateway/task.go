package gateway

import (
	"fmt"
	"time"
)

// Task is a grant-bound, subject-scoped asynchronous execution handle (spec §21,
// conformance/vectors/task-rules.json). A capability whose work outlives a single
// request returns a Task instead of a result; the Planner/Host later fetches status
// and the eventual result.
//
// A Task is a `state` handle (spec §5.1): typed, expiring, and scoped to the
// subject that created it. Its lifetime and authority are bound to the originating
// grant — the Gateway MUST NOT let a task outlive its grant, and cancelling a task
// revokes its grant.
type Task struct {
	Kind         string  `json:"kind"`
	TaskID       string  `json:"task_id"`
	CapabilityID string  `json:"capability_id"`
	GrantID      string  `json:"grant_id"`
	Subject      string  `json:"subject"`
	Status       string  `json:"status"`
	Progress     float64 `json:"progress,omitempty"`
	CreatedAt    string  `json:"created_at"`
	ExpiresAt    string  `json:"expires_at"`
	ResultRef    string  `json:"result_ref,omitempty"`
	// Cancelled records that tasks/cancel has been called. Cancellation revokes the
	// grant (spec §21): no further effect may be committed under it.
	Cancelled bool `json:"cancelled,omitempty"`
}

// Task status values (spec §21).
const (
	TaskStatusRunning       = "running"
	TaskStatusInputRequired = "input-required"
	TaskStatusCompleted     = "completed"
	TaskStatusCancelled     = "cancelled"
	TaskStatusFailed        = "failed"
)

// Task operations (the request verbs evaluated by EvaluateTask).
const (
	TaskOpGet    = "get"
	TaskOpCancel = "cancel"
	TaskOpUpdate = "update"
	TaskOpInvoke = "invoke"
)

// TaskKind is the discriminator carried by a task handle (spec §21).
const TaskKind = "vcp.task"

// TaskManager owns the in-memory task store and enforces the §21 lifecycle rules.
// It is the Gateway-side authority for tasks; the Planner/Host only holds opaque
// handles. Not safe for concurrent use without external synchronization (the
// reference is single-goroutine, matching the rest of the gateway package).
type TaskManager struct {
	tasks map[string]*Task
}

// NewTaskManager returns an empty TaskManager.
func NewTaskManager() *TaskManager {
	return &TaskManager{tasks: map[string]*Task{}}
}

// CreateTaskParams collects the bindings a task is scoped to (spec §21). The task
// inherits its lifetime from the grant: a Gateway MUST NOT mint a task whose
// expiry exceeds its grant's expiry.
type CreateTaskParams struct {
	TaskID       string
	CapabilityID string
	GrantID      string
	Subject      string
	CreatedAt    time.Time
	ExpiresAt    time.Time
}

// CreateTask registers a running task. It fails if the task expiry is not after
// its creation time, or if a task with the same id already exists (handles are
// unique). `max_calls` accounting is charged once, at task creation, by the caller
// (spec §21); CreateTask does not itself touch the grant's call ledger.
func (m *TaskManager) CreateTask(p CreateTaskParams) (*Task, error) {
	if p.TaskID == "" {
		return nil, fmt.Errorf("task: task_id is required")
	}
	if p.Subject == "" || p.GrantID == "" || p.CapabilityID == "" {
		return nil, fmt.Errorf("task: subject, grant_id and capability_id are required")
	}
	if !p.ExpiresAt.After(p.CreatedAt) {
		return nil, fmt.Errorf("task: expires_at must be after created_at")
	}
	if _, exists := m.tasks[p.TaskID]; exists {
		return nil, fmt.Errorf("task: %q already exists", p.TaskID)
	}
	t := &Task{
		Kind:         TaskKind,
		TaskID:       p.TaskID,
		CapabilityID: p.CapabilityID,
		GrantID:      p.GrantID,
		Subject:      p.Subject,
		Status:       TaskStatusRunning,
		CreatedAt:    p.CreatedAt.UTC().Format(time.RFC3339),
		ExpiresAt:    p.ExpiresAt.UTC().Format(time.RFC3339),
	}
	m.tasks[p.TaskID] = t
	return t, nil
}

// Put inserts an already-constructed task (e.g. one loaded from a vector). It is a
// convenience for tests and for rehydrating handles; it overwrites any existing
// task with the same id.
func (m *TaskManager) Put(t *Task) {
	if t.Kind == "" {
		t.Kind = TaskKind
	}
	m.tasks[t.TaskID] = t
}

// TaskDecision is the verdict of EvaluateTask.
type TaskDecision struct {
	Decision   string // allow | deny
	ReasonCode string
}

// EvaluateTask renders the access/lifecycle verdict for one operation on a task at
// logical time now, by the given subject (spec §21,
// conformance/vectors/task-rules.json). Checks run in a fixed, security-meaningful
// order so the FIRST failure is reported:
//
//  1. Existence    — an unknown task id is denied SUBJECT_MISMATCH (a handle the
//     caller cannot prove ownership of; fail closed).
//  2. Subject scope — the operation MUST be by the owning subject; otherwise
//     SUBJECT_MISMATCH (test #17, cross-subject access).
//  3. Cancellation — a cancelled task has revoked its grant; any effect-bearing
//     operation (invoke/update) is denied GRANT_REVOKED (test #16). A read (get)
//     of a cancelled task is still permitted to its owner so the Host can observe
//     the cancelled status.
//  4. Expiry        — now MUST be before expires_at; otherwise TASK_EXPIRED
//     (test #15, task outlives grant).
//
// Operations that mutate or extend effect (invoke, update, cancel) are treated as
// effect-bearing for the cancellation check; get is read-only.
func (m *TaskManager) EvaluateTask(taskID, op, subject string, now time.Time) TaskDecision {
	t, ok := m.tasks[taskID]
	if !ok {
		// Unknown handle: the caller cannot demonstrate ownership. Fail closed as a
		// subject mismatch rather than leaking task existence.
		return TaskDecision{Decision: DecisionDeny, ReasonCode: ReasonSubjectMismatch}
	}

	// 2. Subject scope (spec §21): a Gateway MUST reject operations from a different
	// subject. Constant-time identifier comparison (spec §3 rule 5).
	if !constantTimeStringEqual(subject, t.Subject) {
		return TaskDecision{Decision: DecisionDeny, ReasonCode: ReasonSubjectMismatch}
	}

	// 3. Cancellation revokes the grant (spec §21). An effect-bearing operation under
	// a cancelled task is denied GRANT_REVOKED.
	if t.Cancelled && isEffectBearingTaskOp(op) {
		return TaskDecision{Decision: DecisionDeny, ReasonCode: ReasonGrantRevoked}
	}

	// 4. Expiry (spec §21): a task MUST NOT outlive its grant. now must be strictly
	// before expires_at.
	exp, err := time.Parse(time.RFC3339, t.ExpiresAt)
	if err != nil {
		// Unparseable expiry => treat as expired (fail closed).
		return TaskDecision{Decision: DecisionDeny, ReasonCode: ReasonTaskExpired}
	}
	if !now.Before(exp) {
		return TaskDecision{Decision: DecisionDeny, ReasonCode: ReasonTaskExpired}
	}

	return TaskDecision{Decision: DecisionAllow, ReasonCode: ReasonOK}
}

// isEffectBearingTaskOp reports whether an operation can commit or extend effect
// under the task's grant (spec §21). get is read-only; invoke/update/cancel are
// effect-bearing and are the operations a cancelled (grant-revoked) task forbids.
func isEffectBearingTaskOp(op string) bool {
	switch op {
	case TaskOpInvoke, TaskOpUpdate, TaskOpCancel:
		return true
	default:
		return false
	}
}

// Get returns the verdict for a tasks/get and, on allow, the task itself. The
// returned *Task is a copy so callers cannot mutate the stored handle.
func (m *TaskManager) Get(taskID, subject string, now time.Time) (TaskDecision, *Task) {
	d := m.EvaluateTask(taskID, TaskOpGet, subject, now)
	if d.Decision != DecisionAllow {
		return d, nil
	}
	t := *m.tasks[taskID]
	return d, &t
}

// Cancel cancels a task on behalf of its owning subject, revoking the underlying
// grant (spec §21). It MUST be performed by the owning subject and before expiry;
// otherwise it returns the corresponding deny verdict and does not mutate state.
// On success the task transitions to cancelled and an AuditEvent is returned for
// the caller to sign/emit (spec §21 requires a cancellation audit event). The
// returned grantID lets the caller revoke the grant in its own grant ledger.
func (m *TaskManager) Cancel(taskID, subject string, now time.Time) (TaskDecision, *AuditEvent) {
	d := m.EvaluateTask(taskID, TaskOpCancel, subject, now)
	if d.Decision != DecisionAllow {
		return d, nil
	}
	t := m.tasks[taskID]
	t.Cancelled = true
	t.Status = TaskStatusCancelled
	ev := &AuditEvent{
		Event:        "vcp.task.cancelled",
		TraceID:      "trace_" + t.GrantID,
		Subject:      t.Subject,
		CapabilityID: t.CapabilityID,
		GrantID:      t.GrantID,
		Decision:     DecisionAllow,
		ReasonCode:   ReasonGrantRevoked,
		Timestamp:    now.UTC().Format(time.RFC3339),
	}
	return d, ev
}

// IsGrantRevoked reports whether the grant behind a task has been revoked by a
// prior cancellation. The Gateway consults this before honoring any invocation
// that names a task's grant (spec §21: cancel = revoke).
func (m *TaskManager) IsGrantRevoked(taskID string) bool {
	t, ok := m.tasks[taskID]
	return ok && t.Cancelled
}
