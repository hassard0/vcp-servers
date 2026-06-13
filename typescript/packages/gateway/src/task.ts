import { randomUUID } from "node:crypto";
import { ReasonCode, type Task, type TaskStatus } from "@vcp/sdk";
import { constantTimeStringEq } from "./verify-manifest.ts";

/**
 * Task lifecycle enforcement (SPEC §21). A task is a typed, expiring `state`
 * handle scoped to the subject that created it; the originating grant governs
 * its whole lifetime; and cancellation REVOKES the grant so no further effect
 * can be committed under it.
 *
 * Verdicts mirror conformance/vectors/task-rules.json:
 *  - SUBJECT_MISMATCH : presented by a subject other than the owner
 *  - TASK_EXPIRED     : now at/after expires_at
 *  - GRANT_REVOKED    : invoke under a grant whose task was cancelled
 */

export type TaskOp = "get" | "update" | "cancel" | "invoke";

export interface TaskVerdict {
  decision: "allow" | "deny";
  reason_code:
    | typeof ReasonCode.OK
    | typeof ReasonCode.SUBJECT_MISMATCH
    | typeof ReasonCode.TASK_EXPIRED
    | typeof ReasonCode.GRANT_REVOKED;
}

export interface CreateTaskInput {
  capability_id: string;
  grant_id: string;
  subject: string;
  /** Absolute task expiry; MUST NOT exceed the grant's expires_at (§21). */
  expires_at: string;
  created_at?: string;
  status?: TaskStatus;
  progress?: number;
}

/**
 * Evaluate one operation against a task at evaluation time `now`. Pure: does not
 * mutate the task; cancellation state is supplied by the caller (it lives in the
 * grant's revocation set). Check order matches the vectors: subject ownership
 * first (do not leak existence to non-owners), then expiry, then revocation.
 */
export function evaluateTaskOp(
  task: Task,
  op: TaskOp,
  by: { subject: string; now: Date; grant_revoked: boolean },
): TaskVerdict {
  // Subject-scoped: any op from a different subject is rejected (§21).
  if (!constantTimeStringEq(by.subject, task.subject)) {
    return { decision: "deny", reason_code: ReasonCode.SUBJECT_MISMATCH };
  }
  // Expiry: a task MUST NOT be operated on past its expiry (§21).
  if (by.now.getTime() >= Date.parse(task.expires_at)) {
    return { decision: "deny", reason_code: ReasonCode.TASK_EXPIRED };
  }
  // Cancellation revokes the grant: any invoke under it is denied (§21).
  if (op === "invoke" && by.grant_revoked) {
    return { decision: "deny", reason_code: ReasonCode.GRANT_REVOKED };
  }
  return { decision: "allow", reason_code: ReasonCode.OK };
}

export interface CancelResult {
  task: Task;
  /** The grant_id that cancellation revoked (cancel == revoke, §21). */
  revoked_grant_id: string;
}

/**
 * In-memory TaskStore/manager (§21). Holds tasks and the set of grants revoked
 * by task cancellation, so a subsequent invoke under a cancelled task's grant is
 * denied GRANT_REVOKED. Operations are stateless requests (§21) — there is no
 * implicit task session — but the store persists task + revocation state.
 */
export class TaskStore {
  #tasks = new Map<string, Task>();
  #revokedGrants = new Set<string>();

  /** Create a grant-bound task handle. Charges max_calls once, at creation. */
  create(input: CreateTaskInput): Task {
    const task: Task = {
      kind: "vcp.task",
      task_id: "task_" + randomUUID(),
      capability_id: input.capability_id,
      grant_id: input.grant_id,
      subject: input.subject,
      status: input.status ?? "running",
      ...(input.progress !== undefined ? { progress: input.progress } : {}),
      created_at: input.created_at ?? new Date().toISOString(),
      expires_at: input.expires_at,
      result_ref: null,
    };
    this.#tasks.set(task.task_id, task);
    return task;
  }

  /** Register an externally-built task (e.g. from a conformance vector). */
  put(task: Task): Task {
    this.#tasks.set(task.task_id, task);
    return task;
  }

  /**
   * tasks/get with §21 enforcement. Returns the task only to its owning subject,
   * before expiry; otherwise a structured verdict and no task.
   */
  get(
    task_id: string,
    by: { subject: string; now: Date },
  ): { verdict: TaskVerdict; task?: Task } {
    const task = this.#tasks.get(task_id);
    if (!task) {
      // Unknown handle is treated as a subject mismatch (no existence leak).
      return { verdict: { decision: "deny", reason_code: ReasonCode.SUBJECT_MISMATCH } };
    }
    const verdict = evaluateTaskOp(task, "get", {
      subject: by.subject,
      now: by.now,
      grant_revoked: this.isGrantRevoked(task.grant_id),
    });
    return verdict.decision === "allow" ? { verdict, task } : { verdict };
  }

  /**
   * tasks/cancel: subject-scoped, and cancellation REVOKES the grant (§21). The
   * task transitions to `cancelled` and its grant joins the revoked set so any
   * later invoke under it is denied GRANT_REVOKED.
   */
  cancel(
    task_id: string,
    by: { subject: string; now: Date },
  ): { verdict: TaskVerdict; result?: CancelResult } {
    const task = this.#tasks.get(task_id);
    if (!task) {
      return { verdict: { decision: "deny", reason_code: ReasonCode.SUBJECT_MISMATCH } };
    }
    const verdict = evaluateTaskOp(task, "cancel", {
      subject: by.subject,
      now: by.now,
      grant_revoked: this.isGrantRevoked(task.grant_id),
    });
    if (verdict.decision !== "allow") return { verdict };

    task.status = "cancelled";
    this.#revokedGrants.add(task.grant_id);
    return { verdict, result: { task, revoked_grant_id: task.grant_id } };
  }

  /** Whether a grant has been revoked by task cancellation. */
  isGrantRevoked(grant_id: string): boolean {
    return this.#revokedGrants.has(grant_id);
  }

  /** Directly revoke a grant (used to model cancellation in tests/vectors). */
  revokeGrant(grant_id: string): void {
    this.#revokedGrants.add(grant_id);
  }
}
