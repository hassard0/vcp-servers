import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyGrant } from "../src/grant.ts";
import type { Grant } from "@vcp/sdk";
import { loadVector } from "./helpers.ts";

interface GrantVector {
  grant: Grant;
  now: string;
  attempts: Array<{
    name: string;
    capability: string;
    argument_hash: string;
    call_index: number;
    now?: string;
    expect: { decision: "allow" | "deny"; reason_code: string };
  }>;
}

test("grant-rules vectors: every attempt reproduces decision + reason_code", () => {
  const v = loadVector<GrantVector>("grant-rules.json");
  for (const a of v.attempts) {
    const now = new Date(a.now ?? v.now);
    const verdict = verifyGrant(
      v.grant,
      { capability: a.capability, argument_hash: a.argument_hash },
      now,
      a.call_index,
    );
    assert.equal(verdict.decision, a.expect.decision, `decision mismatch for ${a.name}`);
    assert.equal(verdict.reason_code, a.expect.reason_code, `reason_code mismatch for ${a.name}`);
  }
});
