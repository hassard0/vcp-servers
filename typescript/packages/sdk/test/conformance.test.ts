import { test } from "node:test";
import assert from "node:assert/strict";
import { canonicalJson, hash } from "../src/canonical.ts";
import { contractHash, capabilityId, argumentHash } from "../src/identity.ts";
import { loadVector } from "./helpers.ts";

test("canonical-hash vectors: JCS string + SHA-256 reproduce exactly", () => {
  const v = loadVector<{ cases: Array<{ name: string; value: unknown; canonical: string; sha256: string }> }>(
    "canonical-hash.json",
  );
  for (const c of v.cases) {
    assert.equal(canonicalJson(c.value), c.canonical, `canonical mismatch for ${c.name}`);
    assert.equal(hash(c.value), c.sha256, `sha256 mismatch for ${c.name}`);
  }
});

test("capability-identity vectors: contract_hash + capability_id, mutation => new identity", () => {
  const v = loadVector<{
    contract: Record<string, unknown>;
    contract_hash: string;
    capability_id: string;
    mutated_network: { contract: Record<string, unknown>; contract_hash: string };
  }>("capability-identity.json");

  assert.equal(contractHash(v.contract as never), v.contract_hash);
  assert.equal(capabilityId(v.contract as never), v.capability_id);

  // Mutated contract MUST yield a different identity (rug-pull => new identity).
  const mutHash = contractHash(v.mutated_network.contract as never);
  assert.equal(mutHash, v.mutated_network.contract_hash);
  assert.notEqual(mutHash, v.contract_hash);
});

test("argument-binding vectors: argument_hash, tampered args differ", () => {
  const v = loadVector<{
    arguments: Record<string, unknown>;
    argument_hash: string;
    tampered_arguments: Record<string, unknown>;
    tampered_argument_hash: string;
  }>("argument-binding.json");

  assert.equal(argumentHash(v.arguments), v.argument_hash);
  assert.equal(argumentHash(v.tampered_arguments), v.tampered_argument_hash);
  assert.notEqual(v.argument_hash, v.tampered_argument_hash);
});
