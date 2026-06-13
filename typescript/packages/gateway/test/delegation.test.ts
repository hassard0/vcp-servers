import { test } from "node:test";
import assert from "node:assert/strict";
import {
  buildDelegationChain,
  isWellOrderedChain,
  verifyCredentialAudience,
  verifyGrantAudience,
  checkAttenuation,
  MockTokenExchangeBroker,
  credentialRef,
} from "../src/delegation.ts";
import { loadVector } from "./helpers.ts";

interface DelegationVector {
  chain_cases: Array<{
    name: string;
    user: string;
    agent: string;
    gateway: string;
    provider: string;
    api: string;
    expect_chain: Array<{ role: string; id: string }>;
  }>;
  credential_cases: Array<{
    name: string;
    credential_audience?: string;
    presented_at?: string;
    grant_audience?: string;
    capability?: string;
    expect: { decision: "allow" | "deny"; reason_code: string };
  }>;
  attenuation_cases: Array<{
    name: string;
    parent_scope: string[];
    child_scope: string[];
    expect: { decision: "allow" | "deny"; reason_code?: string };
  }>;
}

test("delegation chain_cases (§26.2): authorizer→delegate→enforcer→executor→resource", () => {
  const v = loadVector<DelegationVector>("delegation.json");
  for (const c of v.chain_cases) {
    const chain = buildDelegationChain({
      user: c.user,
      agent: c.agent,
      gateway: c.gateway,
      provider: c.provider,
      api: c.api,
    });
    assert.ok(isWellOrderedChain(chain), `chain not well-ordered for ${c.name}`);
    assert.deepEqual(chain, c.expect_chain, `chain mismatch for ${c.name}`);
  }
});

test("delegation credential_cases (§26.1): audience binding + grant audience", () => {
  const v = loadVector<DelegationVector>("delegation.json");
  for (const c of v.credential_cases) {
    let verdict: { decision: string; reason_code: string };
    if (c.credential_audience != null && c.presented_at != null) {
      // Exchanged credential bound to Provider A, presented at A or B.
      verdict = verifyCredentialAudience(c.credential_audience, c.presented_at);
    } else if (c.grant_audience != null && c.capability != null) {
      // Grant for one capability presented for another capability.
      verdict = verifyGrantAudience(c.grant_audience, c.capability);
    } else {
      throw new Error(`malformed credential_case ${c.name}`);
    }
    assert.equal(verdict.decision, c.expect.decision, `decision mismatch for ${c.name}`);
    assert.equal(verdict.reason_code, c.expect.reason_code, `reason_code mismatch for ${c.name}`);
  }
});

test("delegation attenuation_cases (§26.2): narrow OK, widen rejected", () => {
  const v = loadVector<DelegationVector>("delegation.json");
  for (const c of v.attenuation_cases) {
    const verdict = checkAttenuation(c.parent_scope, c.child_scope);
    assert.equal(verdict.decision, c.expect.decision, `decision mismatch for ${c.name}`);
    if (c.expect.reason_code) {
      assert.equal(
        verdict.reason_code,
        c.expect.reason_code,
        `reason_code mismatch for ${c.name}`,
      );
    }
  }
});

test("MockTokenExchangeBroker (§26.1): distinct providers get distinct, audience-bound credentials", () => {
  const broker = new MockTokenExchangeBroker();
  const expires_at = "2026-06-13T16:05:00Z";
  const linear = broker.exchange({
    subject: "user:123",
    actor: "agent:triage",
    audience: "https://api.linear.app",
    scope: ["issues.write"],
    expires_at,
  });
  const slack = broker.exchange({
    subject: "user:123",
    actor: "agent:triage",
    audience: "https://slack.com/api",
    scope: ["chat.write"],
    expires_at,
  });

  // Audience-bound + actor-stamped.
  assert.equal(linear.audience, "https://api.linear.app");
  assert.equal(linear.actor, "agent:triage");
  // Distinct providers ⇒ distinct credential material + thumbprints.
  assert.notEqual(linear.token, slack.token);
  assert.notEqual(linear.credential_jkt, slack.credential_jkt);

  // The linear credential is usable at linear, rejected at slack.
  assert.equal(
    verifyCredentialAudience(linear.audience, "https://api.linear.app").decision,
    "allow",
  );
  assert.equal(
    verifyCredentialAudience(linear.audience, "https://slack.com/api").reason_code,
    "CREDENTIAL_AUDIENCE_MISMATCH",
  );

  // The audit-safe reference never carries the raw token.
  const ref = credentialRef(linear);
  assert.equal(ref.audience, "https://api.linear.app");
  assert.equal(ref.credential_jkt, linear.credential_jkt);
  assert.ok(!("token" in ref));
});
