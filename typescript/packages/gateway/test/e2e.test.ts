import { test } from "node:test";
import assert from "node:assert/strict";
import {
  buildManifest,
  signManifest,
  proposePlan,
  Ed25519Signer,
  type Manifest,
} from "@vcp/sdk";
import { verifyManifest } from "../src/verify-manifest.ts";
import { DefaultPolicy } from "../src/policy.ts";
import { invoke, SampleCalendarProvider } from "../src/invoke.ts";

function calendarManifestBuild() {
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
    output_schema: { type: "object", properties: { event_id: { type: "string" } }, required: ["event_id"] },
    effects: {
      class: "write-reversible" as const,
      external_side_effect: true,
      compensating_action: "calendar.delete_event",
    },
    determinism: { class: "idempotent-write" as const, requires_idempotency_key: true, supports_dry_run: true },
    sandbox: { filesystem: "none" as const, network: ["https://calendar.example.com"], secrets: ["calendar.oauth.user_scoped"] },
  };
}

async function setup() {
  const providerSigner = Ed25519Signer.generate(); // signs manifest + attestations
  const gatewaySigner = Ed25519Signer.generate(); // mints grants + signs audit
  const manifest = await signManifest(buildManifest(calendarManifestBuild()), providerSigner);
  return { providerSigner, gatewaySigner, manifest };
}

test("verifyManifest accepts a well-formed signed manifest", async () => {
  const { providerSigner, manifest } = await setup();
  const r = verifyManifest(manifest, { trustedKey: providerSigner.publicKey(), trustedIssuers: ["did:web:example.com"] });
  assert.equal(r.ok, true);
  assert.equal(r.capability_id, manifest.capability.id);
});

test("rug pull (§4 / §18 test 2): mutated contract => CONTRACT_HASH_MISMATCH", async () => {
  const { providerSigner, manifest } = await setup();
  // Widen sandbox.network after signing without recomputing identity.
  const tampered: Manifest = JSON.parse(JSON.stringify(manifest));
  tampered.capability.sandbox.network.push("https://evil.example");
  const r = verifyManifest(tampered, { trustedKey: providerSigner.publicKey() });
  assert.equal(r.ok, false);
  assert.equal(r.reason_code, "CONTRACT_HASH_MISMATCH");
});

test("forged signature (§18 test 2): wrong key => SIGNATURE_INVALID", async () => {
  const { manifest } = await setup();
  const attacker = Ed25519Signer.generate();
  const r = verifyManifest(manifest, { trustedKey: attacker.publicKey() });
  assert.equal(r.ok, false);
  assert.equal(r.reason_code, "SIGNATURE_INVALID");
});

test("untrusted issuer (§5.2 step 3) => ISSUER_UNTRUSTED", async () => {
  const { providerSigner, manifest } = await setup();
  const r = verifyManifest(manifest, { trustedKey: providerSigner.publicKey(), trustedIssuers: ["did:web:other.example"] });
  assert.equal(r.ok, false);
  assert.equal(r.reason_code, "ISSUER_UNTRUSTED");
});

test("§16 worked example: email->calendar metadata flow, approved plan, succeeds end-to-end", async () => {
  const { providerSigner, gatewaySigner, manifest } = await setup();
  const provider = new SampleCalendarProvider(providerSigner);
  const policy = new DefaultPolicy();

  const args = {
    title: "Demo with Alex",
    start: "2026-06-17T14:00:00-04:00",
    end: "2026-06-17T14:30:00-04:00",
  };
  const { plan_hash } = proposePlan([
    {
      id: "s1",
      capability: manifest.capability.id,
      arguments: args,
      effect: "write-reversible",
      consumes: [{ source: "email.inbox", label: "untrusted_resource_data", classification: "personal" }],
      why: "Schedule the demo Alex requested by email.",
    },
  ]);

  const outcome = await invoke(
    {
      subject: "user:123",
      model: "agent:researcher",
      host: "ide.example",
      manifest,
      arguments: args,
      plan_hash,
      // Email content flows into calendar event metadata (allowed, §16 step 5).
      data_flows: [{ from: "email.inbox", to: "calendar.create_event", classification: "personal" }],
      user_approved: true,
      jkt: "sha256:" + "0".repeat(64),
    },
    {
      manifestTrustedKey: providerSigner.publicKey(),
      trustedIssuers: ["did:web:example.com"],
      policy,
      gatewaySigner,
      provider,
    },
  );

  assert.equal(outcome.ok, true, `expected success, got ${outcome.reason_code}`);
  assert.ok((outcome.result as { event_id?: string }).event_id);
  // Audit trail: grant minted + invocation recorded.
  const events = outcome.audit.map((e) => e.event);
  assert.ok(events.includes("vcp.grant.minted"));
  assert.ok(events.includes("vcp.capability.invoked"));
  // Every audit event is signed.
  for (const e of outcome.audit) {
    assert.ok(e.signature?.value, "audit event must be signed");
  }
});

test("§18 test 10: write without user approval is denied APPROVAL_REQUIRED", async () => {
  const { providerSigner, gatewaySigner, manifest } = await setup();
  const outcome = await invoke(
    {
      subject: "user:123",
      manifest,
      arguments: { title: "x", start: "2026-06-17T14:00:00-04:00", end: "2026-06-17T14:30:00-04:00" },
      plan_hash: "sha256:" + "1".repeat(64),
      user_approved: false,
      jkt: "sha256:" + "0".repeat(64),
    },
    {
      manifestTrustedKey: providerSigner.publicKey(),
      policy: new DefaultPolicy(),
      gatewaySigner,
      provider: new SampleCalendarProvider(providerSigner),
    },
  );
  assert.equal(outcome.ok, false);
  assert.equal(outcome.reason_code, "APPROVAL_REQUIRED");
});

test("§12 / §18 test: classified email -> external Slack flow is denied DATA_FLOW_FORBIDDEN", async () => {
  const { providerSigner, gatewaySigner, manifest } = await setup();
  const outcome = await invoke(
    {
      subject: "user:123",
      manifest,
      arguments: { title: "x", start: "2026-06-17T14:00:00-04:00", end: "2026-06-17T14:30:00-04:00" },
      plan_hash: "sha256:" + "2".repeat(64),
      data_flows: [{ from: "email.inbox", to: "slack.post_message", classification: "confidential" }],
      user_approved: true,
      jkt: "sha256:" + "0".repeat(64),
    },
    {
      manifestTrustedKey: providerSigner.publicKey(),
      policy: new DefaultPolicy(),
      gatewaySigner,
      provider: new SampleCalendarProvider(providerSigner),
    },
  );
  assert.equal(outcome.ok, false);
  assert.equal(outcome.reason_code, "DATA_FLOW_FORBIDDEN");
});
