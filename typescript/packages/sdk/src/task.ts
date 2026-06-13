// Asynchronous execution: task handles (SPEC §21). A task is a typed, expiring
// `state` handle (§5.1) scoped to the subject that created it and governed for
// its whole lifetime by the originating grant. cancel == revoke.

export type TaskStatus =
  | "running"
  | "input-required"
  | "completed"
  | "cancelled"
  | "failed";

/** A task handle returned by an async invocation instead of an inline result. */
export interface Task {
  kind: "vcp.task";
  task_id: string;
  capability_id: string;
  /** The grant whose lifetime governs the whole task (§21). */
  grant_id: string;
  /** The subject that created the task; only this subject may operate on it. */
  subject: string;
  status: TaskStatus;
  progress?: number;
  created_at: string;
  /** A task MUST NOT outlive its grant's expires_at (§21). */
  expires_at: string;
  /** Reference to the eventual attested result, when completed. */
  result_ref?: string | null;
}
