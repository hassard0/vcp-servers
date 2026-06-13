"""Environment / workload attestation tests (SPEC §27).

Covers:

* the SDK :class:`StatementAttester` / :class:`EnvironmentStatement` round-trip
  (signed §27.3 statement, bound to the Gateway challenge nonce);
* the gateway-side :func:`verify_environment_attestation` verdicts beyond the
  pure vector replay (the vector replay itself lives in test_conformance.py);
* **security-suite test 19 (§18 / §27):** a capability whose
  ``effects.requires_attestation`` is true denies grant minting when no valid
  environment statement is presented (``ATTESTATION_REQUIRED`` / no grant), and
  mints — attaching an ``attestation_ref`` to the grant and the audit event —
  when a valid statement is presented;
* a NORMAL capability (no ``requires_attestation``) still mints unchanged, with
  zero added friction and no attestation_ref.
"""

from __future__ import annotations

import unittest

from vcp_gateway import (
    DefaultPolicy,
    Gateway,
    GatewayError,
    InMemoryProvider,
    verify_environment_attestation,
)
from vcp_sdk import (
    EnvironmentStatement,
    StatementAttester,
    build_manifest,
    default_signer,
    propose_plan,
)
from vcp_sdk import reason_codes as rc

# The trusted build digest shared with environment-attestation.json.
_TRUSTED_BUILD = "sha256:" + "ab" * 31 + "ab"
_NONCE = "nonce-abc-123"
_NOW = "2026-06-13T16:00:00Z"
_EXP = "2026-06-13T16:30:00Z"


def _input_schema():
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "title": {"type": "string"},
            "start": {"type": "string"},
            "end": {"type": "string"},
        },
        "required": ["title", "start", "end"],
    }


def _manifest(signer, *, requires_attestation: bool):
    effects = {
        "class": "write-reversible",
        "external_side_effect": True,
        "requires_user_approval": True,
        "compensating_action": "calendar.delete_event",
    }
    if requires_attestation:
        effects["requires_attestation"] = True
    return build_manifest(
        issuer="did:web:example.com",
        provider="example.calendar",
        name="calendar.create_event",
        version="1.2.0",
        input_schema=_input_schema(),
        output_schema={
            "type": "object",
            "properties": {"event_id": {"type": "string"}},
            "required": ["event_id"],
        },
        effects=effects,
        determinism={
            "class": "idempotent-write",
            "requires_idempotency_key": True,
            "supports_dry_run": True,
        },
        sandbox={
            "filesystem": "none",
            "network": ["https://calendar.example.com"],
            "secrets": ["calendar.oauth.user_scoped"],
        },
        summary_for_user="Create a calendar event after approval.",
        summary_for_model="Create a calendar event. Requires explicit approval.",
        signer=signer,
    )


class StatementAttesterSdk(unittest.TestCase):
    """SDK: StatementAttester produces a signed §27.3 statement bound to a nonce."""

    def test_statement_shape_and_nonce_binding(self):
        att = StatementAttester(
            subject_role="provider",
            issuer="did:web:example.calendar",
            build_digest=_TRUSTED_BUILD,
            boot_epoch="epoch-1",
            container_digest="sha256:" + "cd" * 32,
        )
        stmt = att.statement(nonce=_NONCE, expires_at=_EXP)
        self.assertIsInstance(stmt, EnvironmentStatement)
        doc = stmt.to_dict()
        self.assertEqual(doc["kind"], "vcp.environment.attestation")
        self.assertEqual(doc["tier"], "statement")
        self.assertEqual(doc["subject_role"], "provider")
        self.assertEqual(doc["build_digest"], _TRUSTED_BUILD)
        self.assertEqual(doc["container_digest"], "sha256:" + "cd" * 32)
        self.assertEqual(doc["nonce"], _NONCE)
        self.assertEqual(doc["expires_at"], _EXP)
        self.assertIn("signature", doc)
        self.assertIn("value", doc["signature"])

    def test_signature_verifies_and_gateway_accepts(self):
        signer = default_signer()
        att = StatementAttester(
            subject_role="provider",
            issuer="did:web:example.calendar",
            build_digest=_TRUSTED_BUILD,
            boot_epoch="epoch-1",
            signer=signer,
        )
        doc = att.attest(nonce=_NONCE, expires_at=_EXP)
        # With a verifier supplied, the §27.3 signature is checked too.
        verdict = verify_environment_attestation(
            doc,
            requires_attestation=True,
            challenge_nonce=_NONCE,
            now=_NOW,
            trusted_build_digests={_TRUSTED_BUILD},
            verifier=signer.verifier(),
        )
        self.assertEqual(verdict["decision"], "allow")
        self.assertEqual(verdict["reason_code"], rc.OK)

    def test_tampered_signature_is_invalid(self):
        signer = default_signer()
        att = StatementAttester(
            subject_role="provider",
            issuer="x",
            build_digest=_TRUSTED_BUILD,
            boot_epoch="e",
            signer=signer,
        )
        doc = att.attest(nonce=_NONCE, expires_at=_EXP)
        doc["build_digest"] = "sha256:" + "00" * 32  # break the signed body
        verdict = verify_environment_attestation(
            doc,
            requires_attestation=True,
            challenge_nonce=_NONCE,
            now=_NOW,
            trusted_build_digests={_TRUSTED_BUILD, "sha256:" + "00" * 32},
            verifier=signer.verifier(),
        )
        self.assertEqual(verdict["decision"], "deny")
        self.assertEqual(verdict["reason_code"], rc.ATTESTATION_INVALID)

    def test_bad_role_rejected(self):
        with self.assertRaises(ValueError):
            StatementAttester(
                subject_role="bogus", issuer="x", build_digest="y", boot_epoch="z"
            )


class _GatewayScenario(unittest.TestCase):
    def setUp(self):
        self.gw_signer = default_signer()
        self.prov_signer = default_signer()
        self.att_signer = default_signer()

    def _gateway(self, *, with_trust: bool):
        return Gateway(
            policy=DefaultPolicy(),
            signer=self.gw_signer,
            trusted_issuers={"did:web:example.com"},
            trusted_build_digests={_TRUSTED_BUILD} if with_trust else set(),
        )

    def _provider(self, cap_id):
        def handler(args, dry_run):
            return {"event_id": "evt_123"}

        return InMemoryProvider(cap_id, signer=self.prov_signer, handler=handler)

    def _invoke(self, gateway, manifest, *, statement=None, challenge_nonce=None):
        cap_id = manifest["capability"]["id"]
        args = {"title": "Demo", "start": "2026-06-17T14:00:00Z", "end": "2026-06-17T14:30:00Z"}
        plan = propose_plan(
            [{"id": "s1", "capability": cap_id, "arguments": args, "effect": "write-reversible"}]
        )
        ph = plan["plan_hash"]
        return gateway.invoke(
            manifest=manifest,
            provider=self._provider(cap_id),
            arguments=args,
            subject="user:123",
            plan_hash=ph,
            holder_jkt="sha256:" + "0" * 64,
            manifest_verifier=self.gw_signer.verifier(),
            attestation_verifier=self.prov_signer.verifier(),
            approval={"user_approved": True, "plan_hash": ph},
            environment_statement=statement,
            challenge_nonce=challenge_nonce,
            now=__import__("datetime").datetime(2026, 6, 13, 16, 0, 0, tzinfo=__import__("datetime").timezone.utc),
        )


class SecurityTest19RequiresAttestation(_GatewayScenario):
    """Security-suite test 19 (§18/§27): requires_attestation gates grant minting."""

    def _statement(self, **overrides):
        att = StatementAttester(
            subject_role="provider",
            issuer="did:web:example.calendar",
            build_digest=_TRUSTED_BUILD,
            boot_epoch="epoch-1",
            signer=self.att_signer,
        )
        doc = att.attest(nonce=overrides.get("nonce", _NONCE), expires_at=overrides.get("expires_at", _EXP))
        return doc

    def test_missing_statement_denies_no_grant(self):
        gw = self._gateway(with_trust=True)
        manifest = _manifest(self.gw_signer, requires_attestation=True)
        with self.assertRaises(GatewayError) as ctx:
            self._invoke(gw, manifest, statement=None, challenge_nonce=_NONCE)
        self.assertEqual(ctx.exception.reason_code, rc.ATTESTATION_REQUIRED)
        # Fail closed: NO grant minted.
        events = [e["event"] for e in gw.audit.events]
        self.assertNotIn("vcp.grant.minted", events)
        self.assertIn("vcp.attestation.rejected", events)

    def test_wrong_nonce_denies_no_grant(self):
        gw = self._gateway(with_trust=True)
        manifest = _manifest(self.gw_signer, requires_attestation=True)
        stale = self._statement(nonce="stale-nonce")
        with self.assertRaises(GatewayError) as ctx:
            self._invoke(gw, manifest, statement=stale, challenge_nonce=_NONCE)
        self.assertEqual(ctx.exception.reason_code, rc.ATTESTATION_INVALID)
        self.assertNotIn("vcp.grant.minted", [e["event"] for e in gw.audit.events])

    def test_untrusted_build_denies_no_grant(self):
        # Gateway trusts nothing ⇒ the (valid-shape) build digest is untrusted.
        gw = self._gateway(with_trust=False)
        manifest = _manifest(self.gw_signer, requires_attestation=True)
        with self.assertRaises(GatewayError) as ctx:
            self._invoke(gw, manifest, statement=self._statement(), challenge_nonce=_NONCE)
        self.assertEqual(ctx.exception.reason_code, rc.ATTESTATION_INVALID)
        self.assertNotIn("vcp.grant.minted", [e["event"] for e in gw.audit.events])

    def test_valid_statement_mints_grant_with_ref(self):
        gw = self._gateway(with_trust=True)
        manifest = _manifest(self.gw_signer, requires_attestation=True)
        out = self._invoke(gw, manifest, statement=self._statement(), challenge_nonce=_NONCE)
        self.assertEqual(out["result"]["event_id"], "evt_123")
        events = [e["event"] for e in gw.audit.events]
        self.assertIn("vcp.grant.minted", events)
        self.assertIn("vcp.capability.invoked", events)
        # The grant.minted audit event references the verified attestation (§27.4.4).
        minted = next(e for e in gw.audit.events if e["event"] == "vcp.grant.minted")
        self.assertIn("attestation_ref", minted)
        self.assertEqual(minted["attestation_ref"]["result"], "verified")
        self.assertEqual(minted["attestation_ref"]["nonce"], _NONCE)


class NormalCapabilityUnchanged(_GatewayScenario):
    """A capability without requires_attestation mints unchanged (zero friction)."""

    def test_normal_capability_mints_without_attestation(self):
        gw = self._gateway(with_trust=False)  # no build trust configured at all
        manifest = _manifest(self.gw_signer, requires_attestation=False)
        # No statement, no challenge nonce supplied — the common path.
        out = self._invoke(gw, manifest, statement=None, challenge_nonce=None)
        self.assertEqual(out["result"]["event_id"], "evt_123")
        events = [e["event"] for e in gw.audit.events]
        self.assertIn("vcp.grant.minted", events)
        self.assertIn("vcp.capability.invoked", events)
        self.assertNotIn("vcp.attestation.rejected", events)
        # No attestation_ref on the grant audit event (absent ⇒ no friction).
        minted = next(e for e in gw.audit.events if e["event"] == "vcp.grant.minted")
        self.assertNotIn("attestation_ref", minted)


if __name__ == "__main__":
    unittest.main()
