import { test } from "node:test";
import assert from "node:assert/strict";
import { propagateLabel, checkAuthority, checkDataFlow, type SinkKind } from "../src/taint.ts";
import type { TaintLabel } from "@vcp/sdk";
import { loadVector } from "./helpers.ts";

interface TaintVector {
  restrictiveness_order_most_to_least: TaintLabel[];
  propagation_cases: Array<{ name: string; sources: TaintLabel[]; expect_label: TaintLabel }>;
  authority_cases: Array<{
    name: string;
    label: TaintLabel;
    authorizes: boolean;
    expect: { decision: "allow" | "deny"; reason_code?: string };
  }>;
  dataflow_cases: Array<{
    name: string;
    from: string;
    to: string;
    classification: string;
    sink: SinkKind;
    expect: { decision: "allow" | "deny"; reason_code?: string };
  }>;
}

test("taint propagation: most-restrictive label wins", () => {
  const v = loadVector<TaintVector>("taint.json");
  for (const c of v.propagation_cases) {
    assert.equal(propagateLabel(c.sources), c.expect_label, `propagation mismatch for ${c.name}`);
  }
});

test("taint authority: authority from untrusted_* is denied", () => {
  const v = loadVector<TaintVector>("taint.json");
  for (const c of v.authority_cases) {
    const verdict = checkAuthority(c.label, c.authorizes);
    assert.equal(verdict.decision, c.expect.decision, `decision mismatch for ${c.name}`);
    if (c.expect.reason_code) {
      assert.equal(verdict.reason_code, c.expect.reason_code, `reason_code mismatch for ${c.name}`);
    }
  }
});

test("taint data-flow: classified->external forbidden, ->internal-metadata allowed", () => {
  const v = loadVector<TaintVector>("taint.json");
  for (const c of v.dataflow_cases) {
    const verdict = checkDataFlow({ from: c.from, to: c.to, classification: c.classification, sink: c.sink });
    assert.equal(verdict.decision, c.expect.decision, `decision mismatch for ${c.name}`);
    if (c.expect.reason_code) {
      assert.equal(verdict.reason_code, c.expect.reason_code, `reason_code mismatch for ${c.name}`);
    }
  }
});
