"""Conformance: reproduce all five cross-language vectors (the wire contract).

Each test loads the published ground-truth JSON and asserts the Python reference
reproduces the canonical bytes, hashes, identities, grant verdicts, and taint
rules exactly. Passing all five is the bar for the security-relevant core of
VCP-L1/L2 (conformance/README.md).
"""

from __future__ import annotations

import unittest

from vcp_gateway import (
    attenuate,
    authority_decision,
    build_delegation_chain,
    data_flow_decision,
    evaluate_operation,
    most_restrictive,
    verify_credential_audience,
    verify_grant,
    verify_grant_audience,
)
from vcp_sdk import argument_hash, canonical_json, capability_id, contract_hash
from vcp_sdk import hash as vcp_hash
from vcp_sdk import reason_codes as rc

from . import _vectors


class CanonicalHashVector(unittest.TestCase):
    def test_canonical_and_sha256(self):
        data = _vectors.load("canonical-hash.json")
        for case in data["cases"]:
            with self.subTest(case=case["name"]):
                got_canonical = canonical_json(case["value"]).decode("utf-8")
                self.assertEqual(got_canonical, case["canonical"])
                self.assertEqual(vcp_hash(case["value"]), case["sha256"])


class CapabilityIdentityVector(unittest.TestCase):
    def test_contract_hash_and_id(self):
        data = _vectors.load("capability-identity.json")
        self.assertEqual(contract_hash(data["contract"]), data["contract_hash"])
        self.assertEqual(capability_id(data["contract"]), data["capability_id"])

    def test_mutation_changes_identity(self):
        data = _vectors.load("capability-identity.json")
        mutated = data["mutated_network"]
        self.assertEqual(contract_hash(mutated["contract"]), mutated["contract_hash"])
        # The whole point: a widened sandbox.network is a NEW identity.
        self.assertNotEqual(mutated["contract_hash"], data["contract_hash"])


class ArgumentBindingVector(unittest.TestCase):
    def test_argument_hash_and_tamper(self):
        data = _vectors.load("argument-binding.json")
        self.assertEqual(argument_hash(data["arguments"]), data["argument_hash"])
        self.assertEqual(
            argument_hash(data["tampered_arguments"]), data["tampered_argument_hash"]
        )
        self.assertNotEqual(data["argument_hash"], data["tampered_argument_hash"])


class GrantRulesVector(unittest.TestCase):
    def test_all_attempts(self):
        data = _vectors.load("grant-rules.json")
        grant = data["grant"]
        default_now = data["now"]
        for attempt in data["attempts"]:
            with self.subTest(attempt=attempt["name"]):
                now = attempt.get("now", default_now)
                verdict = verify_grant(
                    grant,
                    {
                        "capability": attempt["capability"],
                        "argument_hash": attempt["argument_hash"],
                    },
                    now=now,
                    call_index=attempt["call_index"],
                )
                self.assertEqual(verdict["decision"], attempt["expect"]["decision"])
                self.assertEqual(
                    verdict["reason_code"], attempt["expect"]["reason_code"]
                )


class TaintVector(unittest.TestCase):
    def test_propagation(self):
        data = _vectors.load("taint.json")
        for case in data["propagation_cases"]:
            with self.subTest(case=case["name"]):
                self.assertEqual(
                    most_restrictive(case["sources"]), case["expect_label"]
                )

    def test_authority(self):
        data = _vectors.load("taint.json")
        for case in data["authority_cases"]:
            with self.subTest(case=case["name"]):
                dec = authority_decision(case["label"], case["authorizes"])
                self.assertEqual(dec.decision, case["expect"]["decision"])
                if "reason_code" in case["expect"]:
                    self.assertEqual(dec.reason_code, case["expect"]["reason_code"])

    def test_dataflow(self):
        data = _vectors.load("taint.json")
        for case in data["dataflow_cases"]:
            with self.subTest(case=case["name"]):
                dec = data_flow_decision(
                    classification=case["classification"],
                    sink=case["sink"],
                    from_=case["from"],
                    to=case["to"],
                )
                self.assertEqual(dec.decision, case["expect"]["decision"])
                if "reason_code" in case["expect"]:
                    self.assertEqual(dec.reason_code, case["expect"]["reason_code"])


class ReasonCodeRegistryVector(unittest.TestCase):
    """SPEC §23: every registry `code` MUST be exposed with its category."""

    def test_all_codes_present_with_category(self):
        data = _vectors.load("reason-codes.json")
        for row in data["codes"]:
            with self.subTest(code=row["code"]):
                code = row["code"]
                # Exposed as a module-level constant ...
                self.assertTrue(
                    hasattr(rc, code), f"reason code {code} not exposed as a constant"
                )
                self.assertEqual(getattr(rc, code), code)
                # ... and as an enum member.
                self.assertEqual(rc.ReasonCode[code].value, code)
                # In the registry with the correct category + remediable flag.
                self.assertIn(code, rc.REGISTRY)
                self.assertEqual(rc.category_of(code).value, row["category"])
                self.assertEqual(rc.is_remediable(code), row["remediable"])

    def test_no_extra_or_missing_codes(self):
        data = _vectors.load("reason-codes.json")
        vector_codes = {row["code"] for row in data["codes"]}
        self.assertEqual(set(rc.all_codes()), vector_codes)


class TaskRulesVector(unittest.TestCase):
    """SPEC §21: task lifecycle verdicts (subject scope, expiry, cancel=revoke)."""

    def test_operations(self):
        data = _vectors.load("task-rules.json")
        task = data["task"]
        for op in data["operations"]:
            with self.subTest(op=op["name"]):
                verdict = evaluate_operation(
                    task,
                    op=op["op"],
                    subject=op["subject"],
                    now=op["now"],
                    cancelled=op["cancelled"],
                )
                self.assertEqual(verdict["decision"], op["expect"]["decision"])
                self.assertEqual(verdict["reason_code"], op["expect"]["reason_code"])


class DelegationVector(unittest.TestCase):
    """SPEC §26: OBO chain, per-provider credential binding, attenuation."""

    def test_chain_cases(self):
        data = _vectors.load("delegation.json")
        for case in data["chain_cases"]:
            with self.subTest(case=case["name"]):
                chain = build_delegation_chain(
                    user=case["user"],
                    agent=case["agent"],
                    gateway=case["gateway"],
                    provider=case["provider"],
                    api=case["api"],
                )
                self.assertEqual(chain, case["expect_chain"])

    def test_credential_cases(self):
        data = _vectors.load("delegation.json")
        for case in data["credential_cases"]:
            with self.subTest(case=case["name"]):
                if "credential_audience" in case:
                    verdict = verify_credential_audience(
                        credential_audience=case["credential_audience"],
                        presented_at=case["presented_at"],
                    )
                else:
                    verdict = verify_grant_audience(
                        grant_audience=case["grant_audience"],
                        capability=case["capability"],
                    )
                self.assertEqual(verdict["decision"], case["expect"]["decision"])
                self.assertEqual(
                    verdict["reason_code"], case["expect"]["reason_code"]
                )

    def test_attenuation_cases(self):
        data = _vectors.load("delegation.json")
        for case in data["attenuation_cases"]:
            with self.subTest(case=case["name"]):
                verdict = attenuate(
                    parent_scope=case["parent_scope"],
                    child_scope=case["child_scope"],
                )
                self.assertEqual(verdict["decision"], case["expect"]["decision"])
                if "reason_code" in case["expect"]:
                    self.assertEqual(
                        verdict["reason_code"], case["expect"]["reason_code"]
                    )


if __name__ == "__main__":
    unittest.main()
