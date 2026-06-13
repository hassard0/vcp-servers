"""Zero-to-working VCP: build+sign a capability, run it end to end through the Gateway.

Run it from the ``python/`` directory:

    python examples/hello.py

Runs with the standard library alone — if ``cryptography`` is not installed the
SDK transparently falls back to a *labelled* HMAC signer, so the whole flow still
works (the signatures just announce they are a dev fallback, not real Ed25519).
Install the real thing with ``pip install vcp-python[crypto]``.

What this demonstrates, in order:
  1. Build a tiny capability manifest and sign it.
  2. Print its content-addressed ``capability_id`` (hash of the security contract).
  3. Hand it to the Gateway, which verifies it -> runs policy -> mints a single-use
     grant -> invokes an in-process provider -> verifies the provider's attestation.
"""

from __future__ import annotations

# --- Import resolution -------------------------------------------------------
# We want `python examples/hello.py` to work whether or not the package is
# installed. The unittest suite resolves imports by running from the package
# root (`-t .`); we mirror that by putting the `python/` dir (this file's parent
# directory) on sys.path so `vcp_sdk` / `vcp_gateway` import either way.
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vcp_gateway import DefaultPolicy, Gateway, InMemoryProvider
from vcp_sdk import build_manifest, default_signer, propose_plan


def main() -> None:
    # The Gateway and the provider each own a signer. In VCP these are separate
    # trust domains: the Gateway signs grants/audit; the provider signs the
    # attestation over its result. We verify each against the *other* party's
    # public verifier below, so nobody is trusted on their own say-so.
    gateway_signer = default_signer()
    provider_signer = default_signer()

    # --- 1. Build + sign a tiny, read-only capability manifest ---------------
    # read-only means no external side effect and NO user approval, so this runs
    # unattended. The capability id is derived purely from the security-relevant
    # contract (issuer/name/version/schemas/effects/...), NOT from the summaries —
    # those are display strings excluded from identity (SPEC §4).
    manifest = build_manifest(
        issuer="did:web:example.com",        # who vouches for the contract
        provider="example.echo",             # who runs it
        name="echo.say",
        version="1.0.0",
        input_schema={
            "type": "object",
            "additionalProperties": False,   # strict: the Gateway rejects extra args
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
        output_schema={
            "type": "object",
            "properties": {"echoed": {"type": "string"}},
            "required": ["echoed"],
        },
        # read-only is the friction-free class: no side effect, no approval gate.
        effects={"class": "read-only", "external_side_effect": False},
        determinism={"class": "pure"},
        sandbox={"filesystem": "none", "network": [], "secrets": []},
        summary_for_user="Echo a short string back.",
        summary_for_model="Echo the given text. Read-only, no side effects.",
        signer=gateway_signer,               # sign the manifest so it can be verified
    )

    # --- 2. The content-addressed capability id ------------------------------
    # Same contract bytes anywhere in the world => same id. Tamper with any
    # security-relevant field and the id changes, so a swapped contract can't
    # masquerade as this one.
    capability_id = manifest["capability"]["id"]
    print("capability_id:", capability_id)

    # --- 3. The in-process provider ------------------------------------------
    # A real provider lives behind a network boundary; here it's a function. It
    # re-checks the grant audience and recomputes the argument hash before acting
    # (SPEC §8), then signs an attestation over its result so the Gateway can
    # prove the result really came from THIS capability on THESE arguments.
    provider = InMemoryProvider(
        capability_id,
        signer=provider_signer,
        handler=lambda args, dry_run: {"echoed": args["text"]},
    )

    # The plan_hash binds this call to an approved plan (SPEC §3.3). A grant is
    # only valid for the plan it was minted against, so a stolen grant can't be
    # replayed inside a different plan.
    arguments = {"text": "hello, vcp"}
    plan = propose_plan(
        [{"id": "s1", "capability": capability_id, "arguments": arguments, "effect": "read-only"}]
    )

    # --- 4. Drive the full Gateway pipeline ----------------------------------
    # verify manifest -> validate args (strict schema) -> policy decision ->
    # mint single-use proof-bound grant -> invoke provider -> verify attestation.
    # Any failure raises GatewayError and NO result reaches the caller (fail
    # closed, SPEC §19). We pass each party's verifier so trust is mutual.
    gateway = Gateway(
        policy=DefaultPolicy(),
        signer=gateway_signer,
        trusted_issuers={"did:web:example.com"},  # only accept contracts from this issuer
    )
    out = gateway.invoke(
        manifest=manifest,
        provider=provider,
        arguments=arguments,
        subject="user:alice",
        plan_hash=plan["plan_hash"],
        # The holder key thumbprint binds the grant to its holder (proof of
        # possession, SPEC §7); a leaked grant is useless without the matching key.
        holder_jkt="sha256:" + "0" * 64,
        manifest_verifier=gateway_signer.verifier(),
        attestation_verifier=provider_signer.verifier(),
    )

    # The result is labelled untrusted_tool_result: it carries taint so the
    # planner can't later let it silently authorize a privileged action (SPEC §12).
    print("result:        ", out["result"])
    print("grant_id:      ", out["grant_id"])
    print("attested hash: ", out["attestation"]["result_hash"])
    print("label:         ", out["label"])
    print("audit events:  ", [e["event"] for e in gateway.audit.events])


if __name__ == "__main__":
    main()
