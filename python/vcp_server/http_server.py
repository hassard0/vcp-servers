"""A VCP-HTTP gateway server on the stdlib ``http.server`` (SPEC §15).

`VCP-HTTP` is the production default and is **stateless by default**: one request
is one authorization decision, the body is canonical JSON (§3), the protocol
version and capability hash travel in mandatory headers, and there are no
implicit protocol sessions. This server uses only the Python standard library —
no Flask/FastAPI — to keep the dependency surface minimal.

Endpoints
---------
``GET  /.well-known/vcp-provider`` provider discovery (discovery.schema.json)
``GET  /vcp/capabilities``         signed capability index (ids + manifest hashes)
``POST /vcp/plan``                 verify manifests, run policy, dry-run writes,
                                   return ``plan_hash`` + approval/dry-run needs
``POST /vcp/apply``                given an approved ``plan_hash``, mint grants and
                                   invoke; return results + attestations
``GET  /vcp/audit``                the in-memory signed audit log (§20)

Every call appends a signed audit event. Each request carries a mandatory
``vcp-version`` header and, for plan/apply, a ``vcp-capability-hash`` header that
MUST match the server's current capability-index hash; a mismatch is rejected
(rug-pull / version-skew defense, §4/§15).

The only retained cross-request state is the set of approved ``plan_hash`` values
(plan/apply, §9). That is an explicit, typed, expiring handle (the plan_hash),
not an implicit session: authorization context is never carried implicitly
between requests, and each apply is re-authorized from scratch.
"""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Mapping, Optional

from vcp_gateway import (
    AuditLog,
    DefaultPolicy,
    Gateway,
    GatewayError,
    audit_event,
)
from vcp_sdk import canonical_json
from vcp_sdk import hash as _hash
from vcp_sdk.signing import Signer, default_signer

from . import capabilities
from .provider import SampleProvider

VCP_VERSION = "0.1"
HEADER_VERSION = "vcp-version"
HEADER_CAP_HASH = "vcp-capability-hash"

# How long an approved plan_hash stays applicable (the handle's expiry, §5.1).
PLAN_TTL_SECONDS = 300


class _HttpError(Exception):
    """An HTTP-level rejection carrying a status and a machine-actionable code."""

    def __init__(self, status: int, reason_code: str, message: str = "") -> None:
        super().__init__(message or reason_code)
        self.status = status
        self.reason_code = reason_code
        self.message = message or reason_code


class VCPServerState:
    """The shared, mostly-immutable server state behind the request handlers.

    Manifests are verified once at construction and exposed as a signed
    capability index. The Gateway, provider, and audit log are shared. The plan
    store is the only mutable, lock-guarded cross-request state (plan/apply).
    """

    def __init__(
        self,
        *,
        provider_signer: Optional[Signer] = None,
        gateway_signer: Optional[Signer] = None,
        base_url: str = "http://localhost",
        now_fn=None,
    ) -> None:
        self.provider_signer = provider_signer or default_signer()
        self.gateway_signer = gateway_signer or default_signer()
        self.base_url = base_url.rstrip("/")
        self._now_fn = now_fn or (lambda: datetime.now(timezone.utc))

        # Build + sign the four §16 manifests (one provider key).
        self.manifests = capabilities.build_all_manifests(self.provider_signer)
        self.provider = SampleProvider(self.manifests, signer=self.provider_signer)

        self.gateway = Gateway(
            policy=DefaultPolicy(),
            signer=self.gateway_signer,
            trusted_issuers={capabilities.ISSUER},
            audit_log=AuditLog(),
        )
        # NB: an empty AuditLog is falsy (it defines __len__==0), so the Gateway
        # constructor's ``audit_log or AuditLog()`` would discard one we passed.
        # We therefore adopt whatever AuditLog the Gateway ended up with, so our
        # plan/apply events and the Gateway's grant/invoke events share one log.
        self.audit = self.gateway.audit

        # capability_id -> manifest, and name -> capability_id.
        self._manifest_by_id = {m["capability"]["id"]: m for m in self.manifests.values()}
        self._id_by_name = {n: m["capability"]["id"] for n, m in self.manifests.items()}

        # Plan store: plan_hash -> {plan, approved, expires_at}. Lock-guarded.
        self._plans: dict[str, dict] = {}
        self._lock = threading.Lock()

        self._capability_index = self._build_capability_index()
        self._capability_hash = _hash(self._capability_index)

    # ------------------------------------------------------------------ #
    # Discovery + capability index (§5, §16, discovery.schema.json).
    # ------------------------------------------------------------------ #
    def provider_discovery(self) -> dict:
        return {
            "vcp": VCP_VERSION,
            "provider": "example.workspace",
            "issuer": capabilities.ISSUER,
            "manifest_index": f"{self.base_url}/vcp/capabilities",
            "auth": {"type": "mtls", "resource": f"{self.base_url}/vcp"},
        }

    def _build_capability_index(self) -> dict:
        caps = []
        for name, manifest in sorted(self.manifests.items()):
            cap = manifest["capability"]
            caps.append(
                {
                    "id": cap["id"],
                    "name": cap["name"],
                    "effect": cap["effects"]["class"],
                    "manifest_url": f"{self.base_url}/vcp/manifest/{name}",
                    "manifest_hash": cap["contract_hash"],
                    "provenance": "native",
                }
            )
        return {"capabilities": caps}

    def capability_index(self) -> dict:
        return self._capability_index

    @property
    def capability_hash(self) -> str:
        return self._capability_hash

    def manifest_for_name(self, name: str) -> Optional[dict]:
        return self.manifests.get(name)

    # ------------------------------------------------------------------ #
    # Plan / apply (§9).
    # ------------------------------------------------------------------ #
    def handle_plan(self, body: Mapping[str, Any]) -> dict:
        """Verify manifests, run policy over each step, dry-run writes.

        Returns the ``plan_hash``, per-step decisions, the dry-run diffs for
        writes, and whether approval is required before apply. This call mints
        NO grants and commits NO effects.
        """
        steps = body.get("steps")
        if not isinstance(steps, list) or not steps:
            raise _HttpError(400, "PLAN_MALFORMED", "plan requires non-empty steps[]")

        subject = str(body.get("subject", "user:anonymous"))
        model = body.get("model")
        host = body.get("host")
        # plan_hash is computed by the Gateway over the canonical plan (§9.2).
        plan_doc = {"kind": "vcp.plan", "steps": [dict(s) for s in steps]}
        ph = _hash(plan_doc)

        now = self._now_fn()
        trace_id = ph[7:23]
        step_reports: list[dict] = []
        requires_approval = False

        for step in steps:
            report = self._plan_one_step(step, subject=subject, model=model, plan_hash=ph, now=now)
            if report.get("requires_approval"):
                requires_approval = True
            step_reports.append(report)

        # Persist the plan so a later /vcp/apply can bind to this exact plan_hash.
        with self._lock:
            self._plans[ph] = {
                "plan": plan_doc,
                "subject": subject,
                "model": model,
                "host": host,
                "approved": False,
                "expires_at": time.time() + PLAN_TTL_SECONDS,
                "reports": step_reports,
            }

        self.audit.emit(
            audit_event(
                event="vcp.plan.proposed",
                trace_id=trace_id,
                subject=subject,
                capability_id="vcp:plan:" + ph,
                decision="challenge" if requires_approval else "allow",
                plan_hash=ph,
                model=model,
                host=host,
                reason_code="APPROVAL_REQUIRED" if requires_approval else "READ_ONLY_AUTORUN",
                signer=self.gateway_signer,
            )
        )

        return {
            "plan_hash": ph,
            "requires_approval": requires_approval,
            "steps": step_reports,
        }

    def _plan_one_step(
        self,
        step: Mapping[str, Any],
        *,
        subject: str,
        model: Optional[str],
        plan_hash: str,
        now: datetime,
    ) -> dict:
        """Evaluate one plan step: resolve manifest, validate, dry-run if write."""
        name = step.get("capability")
        manifest = self.manifests.get(str(name))
        report: dict[str, Any] = {"id": step.get("id"), "capability": name}
        if manifest is None:
            report.update(decision="deny", reason_code="UNKNOWN_CAPABILITY",
                          requires_approval=False)
            self._audit_plan_denial(subject, "vcp:cap:" + str(name) + "@unknown",
                                    "UNKNOWN_CAPABILITY", plan_hash, model)
            return report

        cap = manifest["capability"]
        effect = cap["effects"]["class"]
        report["capability_id"] = cap["id"]
        report["effect"] = effect

        is_write = effect in ("write-idempotent", "write-reversible", "write-irreversible")
        data_flows = step.get("data_flows")
        arguments = step.get("arguments", {})

        if not is_write:
            # Read-only: it can run unattended once the plan is accepted. We do
            # a policy probe so a tainted-authority data flow is caught now.
            probe = self._policy_probe(
                manifest, arguments, subject, model, plan_hash, data_flows, approval=None
            )
            report.update(decision=probe["decision"], reason_code=probe.get("reason_code"),
                          requires_approval=False)
            if probe.get("remediation"):
                report["remediation"] = probe["remediation"]
            if probe["decision"] == "deny":
                self._audit_plan_denial(subject, cap["id"], probe.get("reason_code"),
                                        plan_hash, model)
            return report

        # Write: §9 requires plan/apply. First, run policy WITHOUT approval to
        # surface tainted-authority / data-flow denials BEFORE asking the user.
        probe = self._policy_probe(
            manifest, arguments, subject, model, plan_hash, data_flows, approval=None
        )
        if probe["decision"] == "deny":
            report.update(decision="deny", reason_code=probe.get("reason_code"),
                          requires_approval=False)
            if probe.get("remediation"):
                report["remediation"] = probe["remediation"]
            self._audit_plan_denial(subject, cap["id"], probe.get("reason_code"),
                                    plan_hash, model)
            return report

        # Policy is otherwise satisfiable -> produce a dry-run diff for approval.
        try:
            diff = self._dry_run(manifest, arguments, subject, plan_hash, model, data_flows, now)
        except GatewayError as exc:
            report.update(decision="deny", reason_code=exc.reason_code,
                          requires_approval=False)
            return report

        report.update(
            decision="challenge",
            reason_code="APPROVAL_REQUIRED",
            requires_approval=True,
            dry_run_diff=diff,
        )
        return report

    def _audit_plan_denial(self, subject, capability_id, reason_code, plan_hash, model) -> None:
        """Record a signed audit event for a step the policy denied at plan time."""
        self.audit.emit(
            audit_event(
                event="vcp.policy.denied",
                subject=subject,
                capability_id=capability_id,
                decision="deny",
                reason_code=reason_code or "POLICY_DENIED",
                plan_hash=plan_hash,
                model=model,
                signer=self.gateway_signer,
            )
        )

    def _policy_probe(
        self, manifest, arguments, subject, model, plan_hash, data_flows, approval
    ) -> dict:
        """Run manifest verify + schema + policy with no grant/commit."""
        from vcp_gateway import make_policy_request, verify_manifest, validate_arguments
        from vcp_sdk import argument_hash

        try:
            cap = verify_manifest(
                manifest,
                verifier=self.provider_signer.verifier(),
                trusted_issuers={capabilities.ISSUER},
            )
            validate_arguments(arguments, cap["input_schema"])
        except Exception as exc:  # VerificationError
            code = getattr(exc, "reason_code", "VERIFICATION_FAILED")
            return {"decision": "deny", "reason_code": code}

        req = make_policy_request(
            subject=subject,
            capability=cap["id"],
            argument_hash=argument_hash(arguments),
            effect=cap["effects"]["class"],
            arguments=arguments,
            model=model,
            plan_hash=plan_hash,
            data_flows=list(data_flows) if data_flows else None,
            determinism=cap.get("determinism", {}).get("class"),
            approval=approval,
        )
        return self.gateway.policy.decide(req)

    def _dry_run(self, manifest, arguments, subject, plan_hash, model, data_flows, now) -> dict:
        """Invoke the provider with dry_run=True to get the would-be effect (§9.4).

        The Gateway path requires an approval to mint a grant for a write; to get
        an unattended dry-run diff we approve THIS exact plan_hash internally for
        the dry-run only — nothing is committed (effect_committed=False).
        """
        cap_id = manifest["capability"]["id"]
        prov = self.provider.for_capability(cap_id)
        out = self.gateway.invoke(
            manifest=manifest,
            provider=prov,
            arguments=arguments,
            subject=subject,
            plan_hash=plan_hash,
            holder_jkt=self.gateway_signer.jkt(),
            manifest_verifier=self.provider_signer.verifier(),
            attestation_verifier=self.provider.verifier,
            data_flows=data_flows,
            approval={"user_approved": True, "plan_hash": plan_hash},
            model=model,
            host=None,
            now=now,
            dry_run=True,
        )
        return out["result"]

    def approve_plan(self, plan_hash: str) -> bool:
        """Mark an exact plan_hash approved (simulates user consent, §9.5)."""
        with self._lock:
            rec = self._plans.get(plan_hash)
            if rec is None or rec["expires_at"] < time.time():
                return False
            rec["approved"] = True
            return True

    def handle_apply(self, body: Mapping[str, Any]) -> dict:
        """Apply an approved plan: mint grants and invoke each step (§9.6).

        A write step requires the plan to be approved (the user approved the
        exact dry-run diff). Read-only steps run regardless. An apply of a write
        whose plan_hash was never approved is rejected ``APPROVAL_REQUIRED``.
        """
        plan_hash = body.get("plan_hash")
        if not isinstance(plan_hash, str):
            raise _HttpError(400, "PLAN_HASH_REQUIRED", "apply requires plan_hash")

        with self._lock:
            rec = self._plans.get(plan_hash)
            if rec is None:
                raise _HttpError(404, "UNKNOWN_PLAN", "no such plan_hash")
            if rec["expires_at"] < time.time():
                raise _HttpError(410, "PLAN_EXPIRED", "plan_hash handle expired")
            approved = bool(rec["approved"])
            plan_doc = rec["plan"]
            subject = rec["subject"]
            model = rec["model"]
            host = rec["host"]
            reports = rec["reports"]

        now = self._now_fn()
        results: list[dict] = []
        report_by_id = {r.get("id"): r for r in reports}

        for step in plan_doc["steps"]:
            sid = step.get("id")
            name = step.get("capability")
            manifest = self.manifests.get(str(name))
            rpt = report_by_id.get(sid, {})
            if manifest is None:
                results.append({"id": sid, "capability": name, "decision": "deny",
                                "reason_code": "UNKNOWN_CAPABILITY"})
                continue
            cap = manifest["capability"]
            effect = cap["effects"]["class"]
            is_write = effect in ("write-idempotent", "write-reversible", "write-irreversible")
            data_flows = step.get("data_flows")
            arguments = step.get("arguments", {})

            # If planning already denied this step (e.g. tainted authority),
            # apply MUST NOT execute it.
            if rpt.get("decision") == "deny":
                results.append({
                    "id": sid, "capability": name, "decision": "deny",
                    "reason_code": rpt.get("reason_code"),
                    "remediation": rpt.get("remediation"),
                })
                continue

            approval = (
                {"user_approved": True, "plan_hash": plan_hash}
                if (is_write and approved)
                else None
            )
            try:
                out = self.gateway.invoke(
                    manifest=manifest,
                    provider=self.provider.for_capability(cap["id"]),
                    arguments=arguments,
                    subject=subject,
                    plan_hash=plan_hash,
                    holder_jkt=self.gateway_signer.jkt(),
                    manifest_verifier=self.provider_signer.verifier(),
                    attestation_verifier=self.provider.verifier,
                    data_flows=data_flows,
                    approval=approval,
                    model=model,
                    host=host,
                    now=now,
                    dry_run=False,
                )
                results.append({
                    "id": sid,
                    "capability": name,
                    "capability_id": cap["id"],
                    "effect": effect,
                    "decision": "allow",
                    "result": out["result"],
                    "attestation": out["attestation"],
                    "grant_id": out["grant_id"],
                    "label": out["label"],
                })
            except GatewayError as exc:
                results.append({
                    "id": sid,
                    "capability": name,
                    "effect": effect,
                    "decision": exc.decision,
                    "reason_code": exc.reason_code,
                })

        return {"plan_hash": plan_hash, "approved": approved, "results": results}

    # ------------------------------------------------------------------ #
    # Audit (§20).
    # ------------------------------------------------------------------ #
    def audit_events(self) -> list[dict]:
        return list(self.audit.events)


def make_handler(state: VCPServerState):
    class VCPRequestHandler(BaseHTTPRequestHandler):
        server_version = "VCP-HTTP/0.1"
        protocol_version = "HTTP/1.1"

        # Silence default stderr logging during tests/demo.
        def log_message(self, fmt, *args):  # noqa: N802
            pass

        # -- helpers ---------------------------------------------------- #
        def _send_json(self, status: int, payload: Mapping[str, Any]) -> None:
            body = canonical_json(payload)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header(HEADER_VERSION, VCP_VERSION)
            self.send_header(HEADER_CAP_HASH, state.capability_hash)
            self.end_headers()
            self.wfile.write(body)

        def _send_error_json(self, err: _HttpError) -> None:
            self._send_json(err.status, {
                "decision": "deny",
                "reason_code": err.reason_code,
                "message": err.message,
            })

        def _require_version(self) -> None:
            ver = self.headers.get(HEADER_VERSION)
            if ver is None:
                raise _HttpError(400, "VCP_VERSION_HEADER_REQUIRED",
                                 f"missing mandatory {HEADER_VERSION} header")
            if ver != VCP_VERSION:
                raise _HttpError(400, "VCP_VERSION_MISMATCH",
                                 f"server speaks {VCP_VERSION}, client sent {ver!r}")

        def _require_capability_hash(self) -> None:
            sent = self.headers.get(HEADER_CAP_HASH)
            if sent is None:
                raise _HttpError(400, "CAPABILITY_HASH_HEADER_REQUIRED",
                                 f"missing mandatory {HEADER_CAP_HASH} header")
            if sent != state.capability_hash:
                # Capability set changed since the client last looked: rug-pull /
                # version-skew defense (§4, §15). Reject; client must re-fetch.
                raise _HttpError(409, "CAPABILITY_HASH_MISMATCH",
                                 "capability index changed; re-fetch /vcp/capabilities")

        def _read_body(self) -> dict:
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length) if length else b""
            if not raw:
                return {}
            try:
                return json.loads(raw.decode("utf-8"))
            except Exception as exc:
                raise _HttpError(400, "BODY_NOT_JSON", str(exc))

        # -- routing ---------------------------------------------------- #
        def do_GET(self):  # noqa: N802
            try:
                self._require_version()
                path = self.path.split("?", 1)[0]
                if path == "/.well-known/vcp-provider":
                    self._send_json(200, state.provider_discovery())
                elif path == "/vcp/capabilities":
                    self._send_json(200, state.capability_index())
                elif path.startswith("/vcp/manifest/"):
                    name = path[len("/vcp/manifest/"):]
                    manifest = state.manifest_for_name(name)
                    if manifest is None:
                        raise _HttpError(404, "UNKNOWN_CAPABILITY", name)
                    self._send_json(200, manifest)
                elif path == "/vcp/audit":
                    self._send_json(200, {"events": state.audit_events()})
                else:
                    raise _HttpError(404, "NOT_FOUND", path)
            except _HttpError as err:
                self._send_error_json(err)

        def do_POST(self):  # noqa: N802
            try:
                self._require_version()
                path = self.path.split("?", 1)[0]
                if path == "/vcp/plan":
                    self._require_capability_hash()
                    body = self._read_body()
                    self._send_json(200, state.handle_plan(body))
                elif path == "/vcp/approve":
                    # Simulated user consent endpoint (demo/test convenience).
                    body = self._read_body()
                    ok = state.approve_plan(str(body.get("plan_hash", "")))
                    self._send_json(200 if ok else 404, {
                        "plan_hash": body.get("plan_hash"),
                        "approved": ok,
                    })
                elif path == "/vcp/apply":
                    self._require_capability_hash()
                    body = self._read_body()
                    self._send_json(200, state.handle_apply(body))
                else:
                    raise _HttpError(404, "NOT_FOUND", path)
            except _HttpError as err:
                self._send_error_json(err)
            except GatewayError as exc:
                self._send_error_json(_HttpError(403, exc.reason_code, str(exc)))

    return VCPRequestHandler


class VCPHTTPServer:
    """A threaded VCP-HTTP server bound to an (optionally ephemeral) port.

    Use as a context manager; the bound port is :attr:`port`. ``port=0`` binds
    an ephemeral port (used by the test suite).
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        *,
        provider_signer: Optional[Signer] = None,
        gateway_signer: Optional[Signer] = None,
        now_fn=None,
    ) -> None:
        self.state = VCPServerState(
            provider_signer=provider_signer,
            gateway_signer=gateway_signer,
            base_url="http://placeholder",
            now_fn=now_fn,
        )
        handler = make_handler(self.state)
        self._httpd = ThreadingHTTPServer((host, port), handler)
        self.host, self.port = self._httpd.server_address[0], self._httpd.server_address[1]
        # Now that we know the real port, fix up URLs in discovery/index.
        self.state.base_url = f"http://{self.host}:{self.port}"
        self.state._capability_index = self.state._build_capability_index()
        self.state._capability_hash = _hash(self.state._capability_index)
        self._thread: Optional[threading.Thread] = None

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self) -> "VCPHTTPServer":
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def __enter__(self) -> "VCPHTTPServer":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()
