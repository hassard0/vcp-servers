import { test } from "node:test";
import assert from "node:assert/strict";
import type { Task } from "@vcp/sdk";
import { TaskStore, evaluateTaskOp, type TaskOp } from "../src/task.ts";
import { loadVector } from "./helpers.ts";

interface TaskRulesVector {
  task: {
    kind: "vcp.task";
    task_id: string;
    capability_id: string;
    grant_id: string;
    subject: string;
    status: string;
    created_at: string;
    expires_at: string;
  };
  operations: Array<{
    name: string;
    op: TaskOp;
    subject: string;
    now: string;
    cancelled: boolean;
    expect: { decision: "allow" | "deny"; reason_code: string };
  }>;
}

test("task-rules vectors (§21): each operation reproduces decision + reason_code", () => {
  const v = loadVector<TaskRulesVector>("task-rules.json");
  const task = v.task as Task;

  for (const o of v.operations) {
    // Each operation is a stateless request (§21). Model `cancelled` by running
    // the op against a store where the task's grant is in the revoked set iff
    // tasks/cancel has been called.
    const store = new TaskStore();
    store.put({ ...task });
    if (o.cancelled) store.revokeGrant(task.grant_id);

    const verdict = evaluateTaskOp(task, o.op, {
      subject: o.subject,
      now: new Date(o.now),
      grant_revoked: store.isGrantRevoked(task.grant_id),
    });

    assert.equal(verdict.decision, o.expect.decision, `decision mismatch for ${o.name}`);
    assert.equal(
      verdict.reason_code,
      o.expect.reason_code,
      `reason_code mismatch for ${o.name}`,
    );
  }
});

test("TaskStore.cancel revokes the grant so a later invoke is denied GRANT_REVOKED (§21, suite test 16)", () => {
  const now = new Date("2026-06-13T16:05:00Z");
  const store = new TaskStore();
  const task = store.create({
    capability_id: "vcp:cap:render.video@sha256:" + "a".repeat(64),
    grant_id: "grant_async_1",
    subject: "user:123",
    expires_at: "2026-06-13T16:30:00Z",
    created_at: "2026-06-13T16:00:00Z",
  });

  // Before cancel: an invoke under the grant is allowed.
  const before = evaluateTaskOp(task, "invoke", {
    subject: "user:123",
    now,
    grant_revoked: store.isGrantRevoked(task.grant_id),
  });
  assert.equal(before.decision, "allow");

  // tasks/cancel revokes the grant and transitions the task.
  const cancel = store.cancel(task.task_id, { subject: "user:123", now });
  assert.equal(cancel.verdict.decision, "allow");
  assert.equal(cancel.result?.revoked_grant_id, "grant_async_1");
  assert.equal(cancel.result?.task.status, "cancelled");

  // After cancel: any invoke under the grant is GRANT_REVOKED.
  const after = evaluateTaskOp(task, "invoke", {
    subject: "user:123",
    now,
    grant_revoked: store.isGrantRevoked(task.grant_id),
  });
  assert.equal(after.decision, "deny");
  assert.equal(after.reason_code, "GRANT_REVOKED");
});

test("TaskStore.get is subject-scoped and expiry-gated (§21, suite tests 15 & 17)", () => {
  const store = new TaskStore();
  const task = store.create({
    capability_id: "vcp:cap:render.video@sha256:" + "b".repeat(64),
    grant_id: "grant_async_2",
    subject: "user:123",
    expires_at: "2026-06-13T16:30:00Z",
    created_at: "2026-06-13T16:00:00Z",
  });
  const now = new Date("2026-06-13T16:05:00Z");

  // Owner, in window: returns the task.
  const ok = store.get(task.task_id, { subject: "user:123", now });
  assert.equal(ok.verdict.decision, "allow");
  assert.equal(ok.task?.task_id, task.task_id);

  // Other subject: SUBJECT_MISMATCH, no task leaked (test 17).
  const other = store.get(task.task_id, { subject: "user:999", now });
  assert.equal(other.verdict.decision, "deny");
  assert.equal(other.verdict.reason_code, "SUBJECT_MISMATCH");
  assert.equal(other.task, undefined);

  // After expiry: TASK_EXPIRED (test 15).
  const expired = store.get(task.task_id, {
    subject: "user:123",
    now: new Date("2026-06-13T16:45:00Z"),
  });
  assert.equal(expired.verdict.decision, "deny");
  assert.equal(expired.verdict.reason_code, "TASK_EXPIRED");
});
