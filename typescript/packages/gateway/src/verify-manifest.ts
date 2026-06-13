import { KeyObject, timingSafeEqual } from "node:crypto";
import {
  contractHash,
  capabilityId,
  extractContract,
  manifestSigningBytes,
  ed25519Verifier,
  type Manifest,
} from "@vcp/sdk";

export interface VerifyManifestOptions {
  /** Public key(s) trusted to sign for the manifest's issuer. */
  trustedKey: KeyObject;
  /** If provided, the issuer MUST be in this allowlist (§5.2 step 3). */
  trustedIssuers?: string[];
}

export interface VerifyManifestResult {
  ok: boolean;
  reason_code?: string;
  capability_id?: string;
}

/**
 * Verify a manifest before exposing it to the Planner (SPEC §5.2):
 *  1. Verify the Ed25519 signature over JCS(manifest without signature).
 *  2. Recompute contract_hash and confirm it matches capability.id and
 *     capability.contract_hash.
 *  3. Confirm the issuer is trusted (if an allowlist is configured).
 *
 * Returns a structured reason_code on failure (fail closed, §19).
 */
export function verifyManifest(
  manifest: Manifest,
  options: VerifyManifestOptions,
): VerifyManifestResult {
  if (manifest.kind !== "capability.manifest" || manifest.vcp !== "0.1") {
    return { ok: false, reason_code: "MANIFEST_MALFORMED" };
  }

  if (options.trustedIssuers && !options.trustedIssuers.includes(manifest.issuer)) {
    return { ok: false, reason_code: "ISSUER_UNTRUSTED" };
  }

  // Recompute identity from the contract subset (§4).
  const recomputedHash = contractHash(extractContract(manifest));
  const recomputedId = capabilityId(extractContract(manifest));

  if (!constantTimeStringEq(recomputedHash, manifest.capability.contract_hash)) {
    return { ok: false, reason_code: "CONTRACT_HASH_MISMATCH" };
  }
  if (!constantTimeStringEq(recomputedId, manifest.capability.id)) {
    return { ok: false, reason_code: "CONTRACT_HASH_MISMATCH" };
  }

  // Verify signature over the canonicalized manifest without its signature.
  const sig = manifest.signature;
  if (!sig || sig.alg !== "Ed25519") {
    return { ok: false, reason_code: "SIGNATURE_ALG_UNSUPPORTED" };
  }
  const verified = ed25519Verifier.verify(
    options.trustedKey,
    manifestSigningBytes(manifest),
    sig.value,
  );
  if (!verified) {
    return { ok: false, reason_code: "SIGNATURE_INVALID" };
  }

  return { ok: true, capability_id: manifest.capability.id };
}

/** Constant-time-ish string comparison (SPEC §3 rule 5). */
export function constantTimeStringEq(a: string, b: string): boolean {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}
