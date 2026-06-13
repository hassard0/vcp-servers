import { test } from "node:test";
import assert from "node:assert/strict";
import {
  REASON_CODE_REGISTRY,
  ReasonCode,
  reasonCodeMeta,
  reasonCategory,
  isRegisteredReasonCode,
} from "../src/reason-codes.ts";
import { loadVector } from "./helpers.ts";

interface ReasonCodesVector {
  codes: Array<{ code: string; category: "allow" | "challenge" | "deny"; remediable: boolean }>;
}

test("reason-code registry (§23): every vector code is exported with correct category + remediable", () => {
  const v = loadVector<ReasonCodesVector>("reason-codes.json");

  // 1. Every code in the normative vector is present as a stable constant and
  //    its metadata (category, remediable) matches exactly.
  for (const c of v.codes) {
    assert.ok(isRegisteredReasonCode(c.code), `missing reason code: ${c.code}`);
    assert.ok(
      Object.prototype.hasOwnProperty.call(ReasonCode, c.code),
      `ReasonCode.${c.code} constant missing`,
    );
    assert.equal((ReasonCode as Record<string, string>)[c.code], c.code);

    const meta = reasonCodeMeta(c.code);
    assert.ok(meta, `no metadata for ${c.code}`);
    assert.equal(meta!.category, c.category, `category mismatch for ${c.code}`);
    assert.equal(meta!.remediable, c.remediable, `remediable mismatch for ${c.code}`);
    assert.equal(reasonCategory(c.code), c.category);
  }

  // 2. The registry is exactly the vector (no extra, no missing) and in order.
  //    The normative registry now has 26 codes (adds ATTESTATION_REQUIRED, §27).
  assert.equal(v.codes.length, 26, "vector must define 26 reason codes");
  assert.equal(
    REASON_CODE_REGISTRY.length,
    v.codes.length,
    "registry length differs from vector",
  );
  for (let i = 0; i < v.codes.length; i++) {
    assert.equal(REASON_CODE_REGISTRY[i].code, v.codes[i].code, `order differs at index ${i}`);
  }
});

test("reason-code registry: unknown codes are rejected", () => {
  assert.equal(isRegisteredReasonCode("NOT_A_REAL_CODE"), false);
  assert.equal(reasonCodeMeta("NOT_A_REAL_CODE"), undefined);
  assert.equal(reasonCategory("NOT_A_REAL_CODE"), undefined);
});
