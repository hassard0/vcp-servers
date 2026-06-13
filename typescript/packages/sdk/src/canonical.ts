import { createHash } from "node:crypto";

/**
 * JSON Canonicalization Scheme (RFC 8785) for the value subset used by VCP:
 * objects, arrays, strings, integers, booleans, and null.
 *
 * Rules implemented (SPEC §3):
 *  - Object keys are sorted by UTF-16 code unit (the default lexicographic
 *    order of String comparison in JS, which is code-unit order).
 *  - No insignificant whitespace.
 *  - Strings use the minimal JSON escaping mandated by RFC 8785 §3.2.2.2,
 *    which is exactly what JSON.stringify on a single string produces: the
 *    seven short escapes (\" \\ \b \f \n \r \t), \u00xx for the remaining
 *    C0 control characters, and every other code point emitted literally as
 *    UTF-8 (no \u escaping of non-ASCII).
 *  - Integers are emitted in their shortest decimal form.
 *
 * Floating point numbers are intentionally NOT supported: RFC 8785 number
 * formatting (ECMAScript Number-to-String / shortest round-trip) is the one
 * genuinely fiddly part and is out of scope for VCP v0.1 vectors. A non-integer
 * number throws.
 */
export function canonicalJson(value: unknown): string {
  return serialize(value);
}

function serialize(value: unknown): string {
  if (value === null) return "null";

  const t = typeof value;

  if (t === "boolean") return value ? "true" : "false";

  if (t === "string") {
    // JSON.stringify of a lone string yields RFC 8785 §3.2.2.2-compliant
    // escaping: short escapes + \u00xx for control chars, literal otherwise.
    return JSON.stringify(value);
  }

  if (t === "number") {
    const n = value as number;
    if (!Number.isFinite(n)) {
      throw new TypeError(`canonicalJson: non-finite number ${n} is not representable`);
    }
    if (!Number.isInteger(n)) {
      throw new TypeError(
        `canonicalJson: non-integer number ${n} is out of scope for VCP v0.1 canonicalization`,
      );
    }
    // Integers: shortest decimal. Normalize -0 to 0.
    return Object.is(n, -0) ? "0" : String(n);
  }

  if (t === "bigint") {
    return (value as bigint).toString();
  }

  if (Array.isArray(value)) {
    return "[" + value.map((el) => serialize(el)).join(",") + "]";
  }

  if (t === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).filter((k) => obj[k] !== undefined);
    // Default Array.sort compares by UTF-16 code unit, which is what RFC 8785
    // requires for member ordering.
    keys.sort();
    const parts: string[] = [];
    for (const k of keys) {
      parts.push(JSON.stringify(k) + ":" + serialize(obj[k]));
    }
    return "{" + parts.join(",") + "}";
  }

  throw new TypeError(`canonicalJson: unsupported value type ${t}`);
}

/** SHA-256 over the UTF-8 bytes of JCS(value), as "sha256:<lowercase-hex>". */
export function hash(value: unknown): string {
  const canonical = canonicalJson(value);
  const digest = createHash("sha256").update(canonical, "utf8").digest("hex");
  return "sha256:" + digest;
}

/** Raw lowercase hex SHA-256 digest (no prefix) of arbitrary bytes/string. */
export function sha256Hex(data: string | Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}
