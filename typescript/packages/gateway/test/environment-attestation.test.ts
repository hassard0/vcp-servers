import { test } from "node:test";
import assert from "node:assert/strict";
import {
  buildManifest,
  signManifest,
  proposePlan,
  Ed25519Signer,
  StatementAttester,
  type EnvironmentStatement,
} from "@vcp/sdk";
import {
  verifyEnvironmentAttestation,
  type VerifiableStatement,
} from "../src/environment-attestation.ts";
import { invoke, SampleCalendarProvider } from "../src/invoke.ts";
import { DefaultPolicy } from "../src/policy.ts";
import { loadVector } from "./helpers.ts";

interface EnvAttVector {
  challenge_nonce: string;
  now: string;
  trusted_build_digests: string[];
  cases: Array<{
    name: string;
    requires_attestation: boolean;
    statement: VerifiableStatement | null;
    expect: { decision: "allow" | "deny"; reason_code: string };
  }>;
}

// ---------------------------------------------------------------------------
// 1. Conformance: drive every case in environment-attestation.json (§27.4).
// ---------------------------------------------------------------------------

test("environment-attestation vectors: every case reproduces decision + reason_code (§27.4)", () => {
  const v = loadVector<EnvAttVector>("environment-attestation.json");
  const now = new Date(v.now);
  for (const c of v.cases) {
    const verdict = verifyEnvironmentAttestation(c.statement, {
      requiresAttestation: c.requires_attestation,
      challengeNonce: v.challenge_nonce,
      now,
      trustedBuildDigests: v.trusted_build_digests,
    });
    assert.equal(verdict.decision, c.expect.decision, `decision mismatch for ${c.name}`);
    assert.equal(
      verdict.reason_code,
      c.expect.reason_code,
      `reason_code mismatch for ${c.name}`,
    );
  }
});

test("not-required adds zero friction even with a bogus statement (§27.1)", () => {
  const verdict = verifyEnvironmentAttestation(
    {
      tier: "statement",
      subject_role: "provider",
      build_digest: "sha256:" + "ff".repeat(32),
      nonce: "totally-wrong",
      expires_at: "2000-01-01T00:00:00Z",
    },
    {
      requiresAttestation: false,
      challengeNonce: "fresh",
      now: new Date("2026-06-13T16:00:00Z"),
      trustedBuildDigests: [],
    },
  );
  assert.deepEqual(verdict, { decision: "allow", reason_code: "OK" });
});

test("StatementAttester produces a signed statement that the Gateway verifies (§27.3)", async () => {
  const signer = Ed25519Signer.generate();
  const attester = new StatementAttester(signer);
  const build = "sha256:" + "ab".repeat(32);
  const statement: EnvironmentStatement = await attester.attest({
    subject_role: "provider",
    issuer: signer.thumbprint(),
    build_digest: build,
    boot_epoch: 1,
    nonce: "nonce-xyz",
    expires_at: "2026-06-13T16:30:00Z",
  });
  assert.equal(statement.kind, "vcp.environment.attestation");
  assert.equal(statement.tier, "statement");
  assert.equal(statement.signature.alg, "Ed25519");

  // Valid, signature-checked.
  const ok = verifyEnvironmentAttestation(statement, {
    requiresAttestation: true,
    challengeNonce: "nonce-xyz",
    now: new Date("2026-06-13T16:00:00Z"),
    trustedBuildDigests: [build],
    attesterPublicKey: signer.publicKey(),
  });
  assert.deepEqual(ok, { decision: "allow", reason_code: "OK" });

  // Tampered build_digest breaks the signature => ATTESTATION_INVALID.
  const forged = { ...statement, build_digest: "sha256:" + "cd".repeat(32) };
  const bad = verifyEnvironmentAttestation(forged, {
    requiresAttestation: true,
    challengeNonce: "nonce-xyz",
    now: new Date("2026-06-13T16:00:00Z"),
    trustedBuildDigests: [forged.build_digest],
    attesterPublicKey: signer.publicKey(),
  });
  assert.equal(bad.decision, "deny");
  assert.equal(bad.reason_code, "ATTESTATION_INVALID");
});

// ---------------------------------------------------------------------------
// 2. Grant-minting gate (§27.4 step 3 / security suite test 19).
// ---------------------------------------------------------------------------

const TRUSTED_BUILD = "sha256:" + "ab".repeat(32);
const NONCE = "nonce-abc-123";

function attestedManifestBuild() {
  return {
    issuer: "did:web:example.com",
    provider: "example.calendar",
    name: "calendar.create_event",
    version: "1.2.0",
    summary_for_user: "Create a calendar event after approval.",
    summary_for_model: "Create a calendar event. Requires explicit approval.",
    input_schema: {
      type: "object",
      additionalProperties: false,
      properties: {
        title: { type: "string" },
        start: { type: "string", format: "date-time" },
        end: { type: "string", format: "date-time" },
      },
      required: ["title", "start", "end"],
    },
    output_schema: {
      type: "object",
      properties: { event_id: { type: "string" } },
      required: ["event_id"],
    },
    effects: {
      class: "write-reversible" as const,
      external_side_effect: true,
      compensating_action: "calendar.delete_event",
      // §27: this capability gates grant minting on environment attestation.
      requires_attestation: true,
    },
    determinism: {
      class: "idempotent-write" as const,
      requires_idempotency_key: true,
      supports_dry_run: true,
    },
    sandbox: {
      filesystem: "none" as const,
      network: ["https://calendar.example.com"],
      secrets: ["calendar.oauth.user_scoped"],
    },
  };
}

const ARGS = {
  title: "Demo with Alex",
  start: "2026-06-17T14:00:00-04:00",
  end: "2026-06-17T14:30:00-04:00",
};

async function setupAttested() {
  const providerSigner = Ed25519Signer.generate();
  const gatewaySigner = Ed25519Signer.generate();
  const manifest = await signManifest(buildManifest(attestedManifestBuild()), providerSigner);
  const { plan_hash } = proposePlan([
    {
      id: "s1",
      capability: manifest.capability.id,
      arguments: ARGS,
      effect: "write-reversible",
      why: "Schedule the demo.",
    },
  ]);
  return { providerSigner, gatewaySigner, manifest, plan_hash };
}

function freshStatement(): VerifiableStatement {
  return {
    tier: "statement",
    subject_role: "provider",
    build_digest: TRUSTED_BUILD,
    nonce: NONCE,
    expires_at: "2026-06-17T15:00:00Z",
  };
}

test("security suite test 19: requires_attestation capability denies grant minting without a valid statement (§27)", async () => {
  const { providerSigner, gatewaySigner, manifest, plan_hash } = await setupAttested();
  const outcome = await invoke(
    {
      subject: "user:123",
      manifest,
      arguments: ARGS,
      plan_hash,
      user_approved: true,
      jkt: "sha256:" + "0".repeat(64),
      // No environment_statement presented.
      challenge_nonce: NONCE,
      now: new Date("2026-06-13T16:00:00Z"),
    },
    {
      manifestTrustedKey: providerSigner.publicKey(),
      trustedIssuers: ["did:web:example.com"],
      policy: new DefaultPolicy(),
      gatewaySigner,
      provider: new SampleCalendarProvider(providerSigner),
      trustedBuildDigests: [TRUSTED_BUILD],
    },
  );
  assert.equal(outcome.ok, false);
  assert.equal(outcome.reason_code, "ATTESTATION_REQUIRED");
  // No grant minted.
  assert.equal(outcome.grant, undefined);
  assert.ok(!outcome.audit.some((e) => e.event === "vcp.grant.minted"));
});

test("requires_attestation capability with a forged (untrusted-build) statement denies ATTESTATION_INVALID, no grant (§27)", async () => {
  const { providerSigner, gatewaySigner, manifest, plan_hash } = await setupAttested();
  const outcome = await invoke(
    {
      subject: "user:123",
      manifest,
      arguments: ARGS,
      plan_hash,
      user_approved: true,
      jkt: "sha256:" + "0".repeat(64),
      environment_statement: { ...freshStatement(), build_digest: "sha256:" + "cd".repeat(32) },
      challenge_nonce: NONCE,
      now: new Date("2026-06-13T16:00:00Z"),
    },
    {
      manifestTrustedKey: providerSigner.publicKey(),
      trustedIssuers: ["did:web:example.com"],
      policy: new DefaultPolicy(),
      gatewaySigner,
      provider: new SampleCalendarProvider(providerSigner),
      trustedBuildDigests: [TRUSTED_BUILD],
    },
  );
  assert.equal(outcome.ok, false);
  assert.equal(outcome.reason_code, "ATTESTATION_INVALID");
  assert.equal(outcome.grant, undefined);
});

test("requires_attestation capability with a valid statement mints a grant carrying attestation_ref (§27.2)", async () => {
  const { providerSigner, gatewaySigner, manifest, plan_hash } = await setupAttested();
  const outcome = await invoke(
    {
      subject: "user:123",
      manifest,
      arguments: ARGS,
      plan_hash,
      user_approved: true,
      jkt: "sha256:" + "0".repeat(64),
      environment_statement: freshStatement(),
      challenge_nonce: NONCE,
      now: new Date("2026-06-13T16:00:00Z"),
    },
    {
      manifestTrustedKey: providerSigner.publicKey(),
      trustedIssuers: ["did:web:example.com"],
      policy: new DefaultPolicy(),
      gatewaySigner,
      provider: new SampleCalendarProvider(providerSigner),
      trustedBuildDigests: [TRUSTED_BUILD],
    },
  );
  assert.equal(outcome.ok, true, `expected success, got ${outcome.reason_code}`);
  assert.ok(outcome.grant);
  // Grant carries the attestation reference (§27.2).
  assert.ok(outcome.grant!.attestation_ref, "grant must carry attestation_ref");
  assert.equal(outcome.grant!.attestation_ref!.nonce, NONCE);
  assert.equal(outcome.grant!.attestation_ref!.subject_role, "provider");
  assert.equal(outcome.grant!.attestation_ref!.tier, "statement");
  // Audit event records the attestation by reference, result verified (§27.4 step 4).
  const minted = outcome.audit.find((e) => e.event === "vcp.grant.minted");
  assert.ok(minted?.attestation_ref, "audit event must carry attestation_ref");
  assert.equal(minted!.attestation_ref!.result, "verified");
  assert.equal(minted!.attestation_ref!.id, outcome.grant!.attestation_ref!.id);
});

test("a normal (non-attested) capability still mints exactly as before — no attestation, no friction (§27.1)", async () => {
  // Same manifest WITHOUT requires_attestation: the grant mints with NO
  // attestation_ref and no attestation inputs supplied at all.
  const providerSigner = Ed25519Signer.generate();
  const gatewaySigner = Ed25519Signer.generate();
  const build = attestedManifestBuild();
  delete (build.effects as { requires_attestation?: boolean }).requires_attestation;
  const manifest = await signManifest(buildManifest(build), providerSigner);
  const { plan_hash } = proposePlan([
    { id: "s1", capability: manifest.capability.id, arguments: ARGS, effect: "write-reversible" },
  ]);

  const outcome = await invoke(
    {
      subject: "user:123",
      manifest,
      arguments: ARGS,
      plan_hash,
      user_approved: true,
      jkt: "sha256:" + "0".repeat(64),
      // No environment_statement, no challenge_nonce — unchanged common path.
    },
    {
      manifestTrustedKey: providerSigner.publicKey(),
      trustedIssuers: ["did:web:example.com"],
      policy: new DefaultPolicy(),
      gatewaySigner,
      provider: new SampleCalendarProvider(providerSigner),
    },
  );
  assert.equal(outcome.ok, true, `expected success, got ${outcome.reason_code}`);
  assert.ok(outcome.grant);
  assert.equal(outcome.grant!.attestation_ref, undefined, "non-attested grant must not carry attestation_ref");
  const minted = outcome.audit.find((e) => e.event === "vcp.grant.minted");
  assert.equal(minted?.attestation_ref, undefined, "non-attested audit must not carry attestation_ref");
});
