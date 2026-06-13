// VCP in ~40 lines: build & sign a capability, then run it through the Gateway.
//
// VCP's core idea: the model/planner is NEVER an authority. A capability is a
// *signed, content-addressed contract*. An enforcing Gateway verifies that
// contract, asks policy, mints a single-use grant bound to the exact call, runs
// the provider, and refuses to return anything until the provider's signed
// attestation matches what it authorized. Authority comes from signatures and
// hashes — never from text a model emitted. This file walks that whole loop.
//
// Run it:  npm run example   (from typescript/)
import {
  buildManifest, // builds an UNSIGNED manifest with a correct content-addressed id
  signManifest, // Ed25519-signs it (signature covers JCS(manifest-without-signature))
  Ed25519Signer, // pluggable Ed25519 signer backed by an in-memory key
  argumentHash, // sha256(JCS(args)) — binds a call to its exact arguments (§8)
  hash, // sha256(JCS(value)) — used by the provider to attest its result
} from "@vcp/sdk";
import { invoke, type Provider } from "@vcp/gateway"; // the enforcing end-to-end flow
import { signAttestation } from "@vcp/gateway"; // a provider signs its result (§9)
import { DefaultPolicy } from "@vcp/gateway"; // a reference taint-aware policy authority
import type { ResultEnvelope } from "@vcp/sdk";

// Two independent keys: one identity owns the capability (signs the manifest AND
// its result attestations); the Gateway has its own key (mints grants, signs audit).
// Separating them is the point — the Gateway trusts the provider's signature, not its word.
const providerSigner = Ed25519Signer.generate();
const gatewaySigner = Ed25519Signer.generate();

// 1. Declare a capability as a CONTRACT. The contract (schemas, effects,
//    determinism, sandbox) is what gets hashed into the identity — summaries are
//    advisory and excluded. effects.class "read-only" means no approval prompt.
const unsigned = buildManifest({
  issuer: "did:web:example.com",
  provider: "example.fx",
  name: "fx.convert",
  version: "1.0.0",
  summary_for_user: "Convert an amount (in minor units, e.g. cents) between currencies at a fixed demo rate.",
  summary_for_model: "Pure read-only currency conversion on integer minor units. No side effects.",
  input_schema: {
    type: "object",
    additionalProperties: false,
    properties: { amount: { type: "number" }, from: { type: "string" }, to: { type: "string" } },
    required: ["amount", "from", "to"],
  },
  output_schema: { type: "object", properties: { converted: { type: "number" } }, required: ["converted"] },
  effects: { class: "read-only", external_side_effect: false }, // read-only ⇒ auto-allowed, no approval
  determinism: { class: "pure", supports_dry_run: false },
  sandbox: { filesystem: "none", network: [], secrets: [] },
});

// 2. Sign it. The capability_id is content-addressed: vcp:cap:<name>@sha256:<contract hash>.
//    Change ANY contract field after signing and the id no longer matches — that's the
//    anti-"rug pull" property. The Gateway recomputes this hash on every verify.
const manifest = await signManifest(unsigned, providerSigner);
console.log("capability_id:", manifest.capability.id);

// 3. A 3-line in-process provider: it recomputes argument_hash (rejecting tampered args),
//    produces a result, and signs an attestation binding capability+args+result together.
const provider: Provider = {
  publicKey: () => providerSigner.publicKey(),
  async invoke(a): Promise<ResultEnvelope> {
    if (argumentHash(a.arguments) !== a.argument_hash) throw new Error("ARGUMENT_HASH_MISMATCH"); // §8
    // The "real" work. VCP v0.1 canonical JSON is integer-only, so we keep the
    // result an integer: convert minor units (cents) at a fixed demo rate of 92%.
    const result = { converted: Math.round((a.arguments.amount as number) * 92 / 100) };
    return { result, attestation: await signAttestation(
      { capability_id: a.capability_id, argument_hash: a.argument_hash, result_hash: hash(result), effect_committed: false },
      providerSigner) };
  },
};

// 4. Run the full gateway loop: verify manifest → policy → mint single-use grant →
//    invoke provider → verify the signed attestation → audit. Fails closed at every step.
const outcome = await invoke(
  {
    subject: "user:alice",
    manifest,
    arguments: { amount: 100, from: "USD", to: "EUR" },
    plan_hash: "sha256:" + "0".repeat(64), // a real planner would hash its proposed plan (proposePlan)
    jkt: providerSigner.thumbprint(), // proof-of-possession: the grant is bound to this key
  },
  {
    manifestTrustedKey: providerSigner.publicKey(), // key the Gateway trusts signed the manifest
    trustedIssuers: ["did:web:example.com"],
    policy: new DefaultPolicy(),
    gatewaySigner,
    provider,
  },
);

// 5. The result is only here because every check passed and the attestation verified.
console.log("ok:", outcome.ok, "result:", outcome.result, "reason:", outcome.reason_code ?? "(allowed)");
console.log("audit events:", outcome.audit.map((e) => e.event).join(", "));
