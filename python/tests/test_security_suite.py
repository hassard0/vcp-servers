"""Security suite (SPEC §22, §26) — interface capabilities + OBO delegation.

These are the security-relevant scenario tests for the 2026-06-13 additions that
are not pure conformance-vector replays:

* **Test 18 — interface capability (§22):** the Host MUST verify a UI artifact's
  ``content_hash`` against the bytes it renders (mismatch → INTERFACE_HASH_MISMATCH)
  and MUST enforce the ``host_actions`` allowlist (a UI cannot invoke a capability
  it did not declare → SANDBOX_VIOLATION).
* **OBO grant integration (§26):** a minted grant carries the delegation chain and a
  token-exchange reference; the exchanged credential is audience-bound and
  unusable at another Provider; audit references it by audience/thumbprint only.
"""

from __future__ import annotations

import hashlib
import unittest

from vcp_gateway import (
    InterfaceError,
    MockTokenExchangeBroker,
    audit_event,
    build_delegation_chain,
    check_host_action,
    content_hash_bytes,
    effective_csp,
    mint_obo_grant,
    verify_credential_audience,
    verify_interface,
)
from vcp_sdk import reason_codes as rc

# A small content-addressed UI artifact (the bytes the Host would render).
_UI_BYTES = b"<html><body><div id='calendar-picker'></div></body></html>"
_UI_HASH = "sha256:" + hashlib.sha256(_UI_BYTES).hexdigest()

# The capability the picker is allowed to call.
_CREATE_EVENT = "calendar.create_event@sha256:" + "9f4c" + "0" * 60


def _interface_block(**overrides):
    block = {
        "surface": "vcp:ui:example.calendar.picker@" + _UI_HASH,
        "content_hash": _UI_HASH,
        "render": "html-sandboxed",
        "csp": {"default-src": ["'none'"], "connect-src": ["https://calendar.example.com"]},
        "permissions": [],
        "host_actions": [_CREATE_EVENT],
        "model_visible": False,
    }
    block.update(overrides)
    return block


class SecurityTest18InterfaceCapability(unittest.TestCase):
    """Security suite test 18 — signed, sandboxed interface capability (§22)."""

    def test_content_hash_matches_rendered_bytes(self):
        report = verify_interface(_interface_block(), _UI_BYTES)
        self.assertEqual(report["decision"], "allow")
        self.assertEqual(report["content_hash"], _UI_HASH)
        self.assertFalse(report["model_visible"])

    def test_content_hash_mismatch_rejected(self):
        tampered = _UI_BYTES + b"<script>steal()</script>"
        with self.assertRaises(InterfaceError) as ctx:
            verify_interface(_interface_block(), tampered)
        self.assertEqual(ctx.exception.reason_code, rc.INTERFACE_HASH_MISMATCH)

    def test_absent_csp_defaults_to_deny_all(self):
        block = _interface_block()
        del block["csp"]
        csp = effective_csp(block)
        self.assertEqual(csp, {"default-src": ["'none'"]})

    def test_host_action_in_allowlist_allowed(self):
        verdict = check_host_action(_interface_block(), _CREATE_EVENT)
        self.assertEqual(verdict["decision"], "allow")

    def test_host_action_not_in_allowlist_rejected(self):
        verdict = check_host_action(_interface_block(), "email.forward@sha256:dead")
        self.assertEqual(verdict["decision"], "deny")
        self.assertEqual(verdict["reason_code"], rc.SANDBOX_VIOLATION)


class OboGrantIntegration(unittest.TestCase):
    """SPEC §26: OBO grant carries chain + token-exchange; credential is bound."""

    def test_grant_carries_chain_and_token_exchange(self):
        broker = MockTokenExchangeBroker()
        cred = broker.exchange(
            subject="user:123",
            actor="agent:triage",
            provider="linear",
            audience="https://api.linear.app",
            scope=["issues.create"],
        )
        chain = build_delegation_chain(
            user="user:123",
            agent="agent:triage",
            gateway="gateway:edge-1",
            provider="linear",
            api="https://api.linear.app",
        )
        grant = mint_obo_grant(
            subject="user:123",
            audience="vcp:cap:linear.create_issue@sha256:" + "1" * 64,
            plan_hash="sha256:" + "a" * 64,
            argument_hash="sha256:" + "b" * 64,
            allowed_effect="write-reversible",
            expires_at="2026-06-13T17:00:00Z",
            holder_jkt="sha256:" + "c" * 64,
            delegation_chain=chain,
            credential=cred,
            resource_scope=["issues.create"],
        )
        self.assertEqual(grant["delegation_chain"], chain)
        self.assertEqual(grant["token_exchange"]["audience"], "https://api.linear.app")
        self.assertEqual(grant["token_exchange"]["actor"], "agent:triage")
        self.assertEqual(
            grant["token_exchange"]["credential_jkt"], cred.credential_jkt
        )
        # The raw token MUST NOT appear anywhere in the grant (§26.1, §26.5).
        self.assertNotIn(cred._token, repr(grant))

    def test_credential_bound_to_provider_a_rejected_at_b(self):
        broker = MockTokenExchangeBroker()
        cred = broker.exchange(
            subject="user:123",
            actor="agent:triage",
            provider="linear",
            audience="https://api.linear.app",
            scope=["issues.create"],
        )
        ok = verify_credential_audience(
            credential_audience=cred.audience, presented_at="https://api.linear.app"
        )
        self.assertEqual(ok["decision"], "allow")
        bad = verify_credential_audience(
            credential_audience=cred.audience, presented_at="https://slack.com/api"
        )
        self.assertEqual(bad["decision"], "deny")
        self.assertEqual(bad["reason_code"], rc.CREDENTIAL_AUDIENCE_MISMATCH)

    def test_distinct_providers_get_distinct_credentials(self):
        broker = MockTokenExchangeBroker()
        a = broker.exchange(
            subject="user:123", actor="agent:triage", provider="linear",
            audience="https://api.linear.app", scope=["issues.create"],
        )
        b = broker.exchange(
            subject="user:123", actor="agent:triage", provider="slack",
            audience="https://slack.com/api", scope=["chat.write"],
        )
        self.assertNotEqual(a.credential_jkt, b.credential_jkt)
        self.assertNotEqual(a.audience, b.audience)

    def test_credential_reference_is_audit_safe(self):
        broker = MockTokenExchangeBroker()
        cred = broker.exchange(
            subject="user:123", actor="agent:triage", provider="linear",
            audience="https://api.linear.app", scope=["issues.create"],
        )
        ref = cred.reference()
        # Audit carries audience + thumbprint by reference, never the token (§26.5).
        self.assertEqual(ref["credential_audience"], "https://api.linear.app")
        self.assertEqual(ref["credential_jkt"], cred.credential_jkt)
        self.assertNotIn(cred._token, str(ref))
        ev = audit_event(
            event="vcp.capability.invoked",
            subject="user:123",
            capability_id="vcp:cap:linear.create_issue@sha256:" + "1" * 64,
            decision="allow",
        )
        ev["delegation_chain"] = build_delegation_chain(
            user="user:123", agent="agent:triage", gateway="gateway:edge-1",
            provider="linear", api="https://api.linear.app",
        )
        ev["credential_audience"] = ref["credential_audience"]
        self.assertIn("delegation_chain", ev)
        self.assertEqual(ev["credential_audience"], "https://api.linear.app")
        self.assertNotIn(cred._token, str(ev))


if __name__ == "__main__":
    unittest.main()
