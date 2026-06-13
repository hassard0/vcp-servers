"""End-to-end Gateway tests, including the §16 worked calendar scenario.

User: "Look at Alex's email and schedule the demo for next week."

Asserts:
* a read-only email step plus a write calendar step flow through the Gateway;
* the email body (untrusted_resource_data) cannot AUTHORIZE the write, but its
  metadata MAY flow to the calendar event (internal-metadata sink);
* if injected text tried to authorize an external send (slack / forward), the
  Gateway denies it (AUTHORITY_FROM_TAINTED_DATA / DATA_FLOW_FORBIDDEN);
* the write requires plan approval; once approved a single-use grant is minted,
  the provider signs an attestation, and the Gateway verifies it.
"""

from __future__ import annotations

import unittest

from vcp_gateway import (
    DefaultPolicy,
    Gateway,
    GatewayError,
    InMemoryProvider,
    make_policy_request,
)
from vcp_sdk import (
    argument_hash,
    build_manifest,
    default_signer,
    propose_plan,
)


def calendar_manifest(signer):
    return build_manifest(
        issuer="did:web:example.com",
        provider="example.calendar",
        name="calendar.create_event",
        version="1.2.0",
        input_schema={
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "title": {"type": "string"},
                "start": {"type": "string"},
                "end": {"type": "string"},
            },
            "required": ["title", "start", "end"],
        },
        output_schema={"type": "object", "properties": {"event_id": {"type": "string"}}, "required": ["event_id"]},
        effects={
            "class": "write-reversible",
            "external_side_effect": True,
            "requires_user_approval": True,
            "compensating_action": "calendar.delete_event",
        },
        determinism={"class": "idempotent-write", "requires_idempotency_key": True, "supports_dry_run": True},
        sandbox={"filesystem": "none", "network": ["https://calendar.example.com"], "secrets": ["calendar.oauth.user_scoped"]},
        summary_for_user="Create a calendar event after approval.",
        summary_for_model="Create a calendar event. Requires explicit approval.",
        signer=signer,
    )


class CalendarScenario(unittest.TestCase):
    def setUp(self):
        self.gw_signer = default_signer()
        self.prov_signer = default_signer()
        self.gateway = Gateway(
            policy=DefaultPolicy(),
            signer=self.gw_signer,
            trusted_issuers={"did:web:example.com"},
        )
        self.manifest = calendar_manifest(self.gw_signer)
        self.cap_id = self.manifest["capability"]["id"]

    def _provider(self):
        def handler(args, dry_run):
            return {"event_id": "evt_123", "event_url": "https://calendar.example.com/evt_123"}

        return InMemoryProvider(self.cap_id, signer=self.prov_signer, handler=handler)

    def _approved_invoke(self, arguments, data_flows):
        plan = propose_plan(
            [
                {"id": "s1", "capability": "vcp:cap:email.read@sha256:" + "a" * 64, "arguments": {"id": "msg1"}, "effect": "read-only"},
                {"id": "s2", "capability": self.cap_id, "arguments": arguments, "effect": "write-reversible", "depends_on": ["s1"]},
            ]
        )
        ph = plan["plan_hash"]
        return self.gateway.invoke(
            manifest=self.manifest,
            provider=self._provider(),
            arguments=arguments,
            subject="user:123",
            plan_hash=ph,
            holder_jkt="sha256:" + "0" * 64,
            manifest_verifier=self.gw_signer.verifier(),
            attestation_verifier=self.prov_signer.verifier(),
            data_flows=data_flows,
            approval={"user_approved": True, "plan_hash": ph},
            model="agent:researcher",
            host="ide.example",
        )

    def test_happy_path_email_metadata_to_calendar(self):
        out = self._approved_invoke(
            {"title": "Demo with Alex", "start": "2026-06-17T14:00:00-04:00", "end": "2026-06-17T14:30:00-04:00"},
            data_flows=[{"from": "email.inbox", "to": "calendar.create_event", "classification": "personal", "label": "untrusted_resource_data", "sink": "internal-metadata"}],
        )
        self.assertEqual(out["result"]["event_id"], "evt_123")
        self.assertTrue(out["attestation"]["effect_committed"])
        self.assertEqual(out["label"], "untrusted_tool_result")
        # An audit trail was produced (grant.minted + capability.invoked).
        events = [e["event"] for e in self.gateway.audit.events]
        self.assertIn("vcp.grant.minted", events)
        self.assertIn("vcp.capability.invoked", events)

    def test_write_without_approval_is_challenged(self):
        plan = propose_plan([{"id": "s2", "capability": self.cap_id, "arguments": {"title": "X", "start": "a", "end": "b"}, "effect": "write-reversible"}])
        with self.assertRaises(GatewayError) as ctx:
            self.gateway.invoke(
                manifest=self.manifest,
                provider=self._provider(),
                arguments={"title": "X", "start": "a", "end": "b"},
                subject="user:123",
                plan_hash=plan["plan_hash"],
                holder_jkt="sha256:" + "0" * 64,
                manifest_verifier=self.gw_signer.verifier(),
                attestation_verifier=self.prov_signer.verifier(),
                data_flows=None,
                approval=None,
            )
        self.assertEqual(ctx.exception.reason_code, "APPROVAL_REQUIRED")

    def test_tainted_data_cannot_authorize_external_send(self):
        """Injected email text authorizing an external send is denied (§12)."""
        policy = DefaultPolicy()
        req = make_policy_request(
            subject="user:123",
            capability="vcp:cap:slack.post_message@sha256:" + "b" * 64,
            argument_hash="sha256:" + "c" * 64,
            effect="write-irreversible",
            data_flows=[{"from": "email.inbox", "to": "slack.post_message", "classification": "confidential", "label": "untrusted_resource_data", "authorizes": True, "sink": "external"}],
        )
        decision = policy.decide(req)
        self.assertEqual(decision["decision"], "deny")
        self.assertEqual(decision["reason_code"], "AUTHORITY_FROM_TAINTED_DATA")

    def test_confidential_to_external_blocked_even_as_data(self):
        policy = DefaultPolicy()
        req = make_policy_request(
            subject="user:123",
            capability="vcp:cap:slack.post_message@sha256:" + "b" * 64,
            argument_hash="sha256:" + "c" * 64,
            effect="write-irreversible",
            approval={"user_approved": True},
            data_flows=[{"from": "email.inbox", "to": "slack.post_message", "classification": "confidential", "label": "user_instruction", "authorizes": False, "sink": "external"}],
        )
        decision = policy.decide(req)
        self.assertEqual(decision["decision"], "deny")
        self.assertEqual(decision["reason_code"], "DATA_FLOW_FORBIDDEN")

    def test_hidden_argument_rejected(self):
        """Extra undeclared arg (additionalProperties:false) is rejected (§17 #8)."""
        with self.assertRaises(GatewayError) as ctx:
            self._approved_invoke(
                {"title": "X", "start": "a", "end": "b", "exfiltrate": "secret"},
                data_flows=None,
            )
        self.assertEqual(ctx.exception.reason_code, "ADDITIONAL_PROPERTIES_FORBIDDEN")

    def test_untrusted_manifest_rejected(self):
        """A manifest signed by the wrong key fails verification (fail closed)."""
        wrong = default_signer()
        with self.assertRaises(GatewayError) as ctx:
            self.gateway.invoke(
                manifest=self.manifest,
                provider=self._provider(),
                arguments={"title": "X", "start": "a", "end": "b"},
                subject="user:123",
                plan_hash="sha256:" + "d" * 64,
                holder_jkt="sha256:" + "0" * 64,
                manifest_verifier=wrong.verifier(),  # wrong key
                attestation_verifier=self.prov_signer.verifier(),
                approval={"user_approved": True, "plan_hash": "sha256:" + "d" * 64},
            )
        self.assertEqual(ctx.exception.reason_code, "SIGNATURE_INVALID")


if __name__ == "__main__":
    unittest.main()
