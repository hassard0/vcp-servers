import {
  generateKeyPairSync,
  sign as edSign,
  verify as edVerify,
  createPublicKey,
  createPrivateKey,
  KeyObject,
} from "node:crypto";
import { canonicalJson, sha256Hex } from "./canonical.ts";

/**
 * A pluggable signing source. The key material never has to live in process
 * memory as raw bytes; an implementation may back this with an HSM, a KMS, or
 * a file. Ed25519 is the default algorithm (SPEC §3).
 */
export interface Signer {
  readonly alg: string;
  /** Sign the given bytes, returning a base64url signature value. */
  sign(message: Uint8Array): Promise<string> | string;
  /** SHA-256 JWK thumbprint of the public key (for proof-of-possession jkt). */
  thumbprint(): string;
  /** The public key, for verifiers. */
  publicKey(): KeyObject;
}

export interface Verifier {
  /** Verify a base64url signature over message with the given public key. */
  verify(publicKey: KeyObject, message: Uint8Array, signature: string): boolean;
}

/** Ed25519 signer backed by an in-memory KeyObject. */
export class Ed25519Signer implements Signer {
  readonly alg = "Ed25519";
  #privateKey: KeyObject;
  #publicKey: KeyObject;

  constructor(privateKey: KeyObject) {
    this.#privateKey = privateKey;
    this.#publicKey = createPublicKey(privateKey);
  }

  static generate(): Ed25519Signer {
    const { privateKey } = generateKeyPairSync("ed25519");
    return new Ed25519Signer(privateKey);
  }

  /** Load from a PKCS#8 PEM string. */
  static fromPem(pem: string): Ed25519Signer {
    return new Ed25519Signer(createPrivateKey(pem));
  }

  sign(message: Uint8Array): string {
    // Ed25519 takes a null algorithm in node:crypto.
    const sig = edSign(null, Buffer.from(message), this.#privateKey);
    return toB64Url(sig);
  }

  publicKey(): KeyObject {
    return this.#publicKey;
  }

  thumbprint(): string {
    return "sha256:" + jwkThumbprint(this.#publicKey);
  }
}

export const ed25519Verifier: Verifier = {
  verify(publicKey: KeyObject, message: Uint8Array, signature: string): boolean {
    try {
      return edVerify(null, Buffer.from(message), publicKey, fromB64Url(signature));
    } catch {
      return false;
    }
  },
};

/**
 * RFC 7638 JWK thumbprint for an OKP/Ed25519 key: SHA-256 over the canonical
 * JWK with members crv, kty, x (lexicographically ordered, no whitespace).
 */
export function jwkThumbprint(publicKey: KeyObject): string {
  const jwk = publicKey.export({ format: "jwk" }) as { crv: string; kty: string; x: string };
  const canonical = canonicalJson({ crv: jwk.crv, kty: jwk.kty, x: jwk.x });
  return sha256Hex(Buffer.from(canonical, "utf8"));
}

export function toB64Url(buf: Buffer | Uint8Array): string {
  return Buffer.from(buf).toString("base64url");
}

export function fromB64Url(s: string): Buffer {
  return Buffer.from(s, "base64url");
}

/** Bytes signed over a document: JCS(document) as UTF-8. */
export function signingBytes(document: unknown): Uint8Array {
  return Buffer.from(canonicalJson(document), "utf8");
}
