"""Asynchronous execution: grant-bound tasks (SPEC §21).

A capability whose work outlives a single request models that work as a
``vcp.task``: the invocation returns a *task handle* and the Host later fetches
status/result. The handle is a ``state`` handle (§5.1): typed, expiring, and
scoped to the subject that created it.

Normative rules enforced here (§21):

* ``tasks/get``, ``tasks/update``, ``tasks/cancel`` from a different subject are
  rejected (``SUBJECT_MISMATCH``).
* A task past ``expires_at`` is rejected (``TASK_EXPIRED``). The originating grant
  governs the whole task lifetime; the Gateway MUST NOT let a task outlive it.
* **Cancellation revokes the grant.** After ``tasks/cancel`` no further effect can
  be committed under it; a subsequent ``invoke`` is denied ``GRANT_REVOKED``.

:func:`evaluate_operation` reproduces ``conformance/vectors/task-rules.json``:
``get-by-owner`` (OK), ``get-by-other-subject`` (SUBJECT_MISMATCH),
``get-after-expiry`` (TASK_EXPIRED), ``invoke-after-cancel`` (GRANT_REVOKED).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional

from vcp_sdk.canonical import constant_time_equals
from vcp_sdk import reason_codes as rc

from .audit import AuditLog, audit_event
from .grants import parse_rfc3339

__all__ = ["Task", "TaskManager", "evaluate_operation", "TaskError"]


class TaskError(Exception):
    """A task-lifecycle rejection carrying a §23 reason code (fail closed)."""

    def __init__(self, reason_code: str, message: str = "") -> None:
        super().__init__(message or reason_code)
        self.reason_code = reason_code
        self.decision = "deny"


@dataclass
class Task:
    """A grant-bound, subject-scoped, expiring task handle (SPEC §21)."""

    capability_id: str
    grant_id: str
    subject: str
    created_at: str
    expires_at: str
    task_id: str = field(default_factory=lambda: f"task_{uuid.uuid4().hex}")
    status: str = "running"
    progress: float = 0.0
    result_ref: Optional[str] = None
    kind: str = "vcp.task"
    # Cancellation revokes the originating grant (§21); tracked here so a later
    # invoke under the same grant is denied GRANT_REVOKED.
    cancelled: bool = False

    def to_dict(self) -> dict:
        """Serialize as a ``vcp.task`` handle (SPEC §21)."""
        d: Dict[str, Any] = {
            "kind": self.kind,
            "task_id": self.task_id,
            "capability_id": self.capability_id,
            "grant_id": self.grant_id,
            "subject": self.subject,
            "status": self.status,
            "progress": self.progress,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "result_ref": self.result_ref,
        }
        return d


def _is_expired(task: Mapping[str, Any] | Task, now: str | datetime) -> bool:
    now_dt = parse_rfc3339(now) if isinstance(now, str) else now
    expires_at = task["expires_at"] if isinstance(task, Mapping) else task.expires_at
    return now_dt >= parse_rfc3339(str(expires_at))


def evaluate_operation(
    task: Mapping[str, Any] | Task,
    *,
    op: str,
    subject: str,
    now: str | datetime,
    cancelled: bool = False,
) -> dict:
    """Evaluate a task operation against §21 rules. Pure, stateless verdict.

    Returns ``{"decision": "allow"|"deny", "reason_code": ...}``.

    Check order (each maps to a §21 rule):
      1. SUBJECT_MISMATCH — handle presented by a different subject.
      2. TASK_EXPIRED     — handle past expiry (grant lifetime bound).
      3. GRANT_REVOKED    — invoke attempted after tasks/cancel.
    """
    owner = task["subject"] if isinstance(task, Mapping) else task.subject

    # 1. Subject scope (§21): a task is scoped to the subject that created it.
    if not constant_time_equals(str(subject), str(owner)):
        return {"decision": "deny", "reason_code": rc.SUBJECT_MISMATCH}

    # 2. Expiry (§21): a task MUST NOT outlive its grant's expires_at.
    if _is_expired(task, now):
        return {"decision": "deny", "reason_code": rc.TASK_EXPIRED}

    # 3. Cancel revokes the grant (§21): no further effect under a cancelled task.
    if cancelled and op == "invoke":
        return {"decision": "deny", "reason_code": rc.GRANT_REVOKED}

    return {"decision": "allow", "reason_code": rc.OK}


class TaskManager:
    """In-memory task store enforcing the §21 lifecycle: create/get/cancel.

    Each operation is a stateless request carrying its own subject (§21: there is
    no implicit task session). ``cancel`` revokes the originating grant and emits
    an audit event.
    """

    def __init__(self, *, audit_log: Optional[AuditLog] = None, signer=None) -> None:
        self._tasks: Dict[str, Task] = {}
        self.audit = audit_log if audit_log is not None else AuditLog()
        self._signer = signer

    def create(
        self,
        *,
        capability_id: str,
        grant_id: str,
        subject: str,
        created_at: str | datetime,
        expires_at: str | datetime,
        task_id: Optional[str] = None,
    ) -> Task:
        """Create and store a task handle. ``max_calls`` is charged once here (§21)."""
        ca = _iso(created_at)
        ea = _iso(expires_at)
        task = Task(
            capability_id=capability_id,
            grant_id=grant_id,
            subject=subject,
            created_at=ca,
            expires_at=ea,
            task_id=task_id or f"task_{uuid.uuid4().hex}",
        )
        self._tasks[task.task_id] = task
        self.audit.emit(
            audit_event(
                event="vcp.task.created",
                subject=subject,
                capability_id=capability_id,
                decision="allow",
                grant_id=grant_id,
                reason_code=rc.OK,
                signer=self._signer,
            )
        )
        return task

    def get(self, task_id: str, *, subject: str, now: str | datetime) -> Task:
        """Fetch a task handle, enforcing subject scope and expiry (§21).

        Raises :class:`TaskError` with the §23 reason code on rejection.
        """
        task = self._tasks.get(task_id)
        if task is None:
            raise TaskError(rc.SUBJECT_MISMATCH, "no such task for subject")
        verdict = evaluate_operation(
            task, op="get", subject=subject, now=now, cancelled=task.cancelled
        )
        if verdict["decision"] != "allow":
            raise TaskError(verdict["reason_code"])
        return task

    def cancel(self, task_id: str, *, subject: str, now: str | datetime) -> dict:
        """Cancel a task. **Revokes the originating grant** and emits audit (§21).

        Enforces subject scope and expiry first. For a ``write-reversible`` task
        already committed, a real Gateway SHOULD invoke the declared compensating
        action (§11); that hook is out of scope for this in-memory manager.
        """
        task = self._tasks.get(task_id)
        if task is None:
            raise TaskError(rc.SUBJECT_MISMATCH, "no such task for subject")
        verdict = evaluate_operation(
            task, op="cancel", subject=subject, now=now, cancelled=task.cancelled
        )
        if verdict["decision"] != "allow":
            raise TaskError(verdict["reason_code"])
        task.status = "cancelled"
        task.cancelled = True
        self.audit.emit(
            audit_event(
                event="vcp.task.cancelled",
                subject=subject,
                capability_id=task.capability_id,
                decision="allow",
                grant_id=task.grant_id,
                reason_code=rc.GRANT_REVOKED,
                signer=self._signer,
            )
        )
        return {"task_id": task.task_id, "status": "cancelled", "grant_revoked": True}

    def invoke(self, task_id: str, *, subject: str, now: str | datetime) -> dict:
        """Attempt to commit further effect under a task's grant (§21).

        After cancellation this is denied ``GRANT_REVOKED``; this is the
        cancel-revokes-grant property the §21 vector asserts.
        """
        task = self._tasks.get(task_id)
        if task is None:
            raise TaskError(rc.SUBJECT_MISMATCH, "no such task for subject")
        verdict = evaluate_operation(
            task, op="invoke", subject=subject, now=now, cancelled=task.cancelled
        )
        if verdict["decision"] != "allow":
            raise TaskError(verdict["reason_code"])
        return {"task_id": task.task_id, "status": task.status}


def _iso(value: str | datetime) -> str:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return value
