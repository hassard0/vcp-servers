import type { JsonSchema } from "@vcp/sdk";

/**
 * Minimal JSON-Schema argument validator covering exactly what the §16
 * manifests use. The load-bearing rule for VCP is §5.2 / §17: every object
 * level carries additionalProperties:false, and a Gateway MUST reject arguments
 * carrying properties not declared in the schema (schema-confusion + hidden-
 * argument-exfiltration defenses, §18 tests 8 and 11).
 *
 * This is intentionally not a full draft-2020-12 validator; it validates the
 * subset (object/array/string/integer/email/date-time) the demo manifests use
 * and fails closed on anything it does not understand.
 */
export interface SchemaError {
  ok: boolean;
  reason_code?: string;
  detail?: string;
}

export function validateArguments(args: unknown, schema: JsonSchema): SchemaError {
  return validate(args, schema, "$");
}

function validate(value: unknown, schema: JsonSchema, path: string): SchemaError {
  const type = schema.type as string | undefined;

  switch (type) {
    case "object": {
      if (value === null || typeof value !== "object" || Array.isArray(value)) {
        return fail("SCHEMA_TYPE_MISMATCH", `${path} expected object`);
      }
      const obj = value as Record<string, unknown>;
      const props = (schema.properties as Record<string, JsonSchema>) ?? {};
      const required = (schema.required as string[]) ?? [];
      const additional = schema.additionalProperties;

      // §17/§18.8: reject undeclared properties when additionalProperties:false.
      if (additional === false) {
        for (const k of Object.keys(obj)) {
          if (!(k in props)) {
            return fail("SCHEMA_ADDITIONAL_PROPERTY", `${path}.${k} is not a declared property`);
          }
        }
      }
      for (const r of required) {
        if (!(r in obj)) {
          return fail("SCHEMA_REQUIRED_MISSING", `${path}.${r} is required`);
        }
      }
      for (const [k, v] of Object.entries(obj)) {
        const sub = props[k];
        if (sub) {
          const r = validate(v, sub, `${path}.${k}`);
          if (!r.ok) return r;
        }
      }
      return { ok: true };
    }
    case "array": {
      if (!Array.isArray(value)) return fail("SCHEMA_TYPE_MISMATCH", `${path} expected array`);
      const items = schema.items as JsonSchema | undefined;
      if (items) {
        for (let i = 0; i < value.length; i++) {
          const r = validate(value[i], items, `${path}[${i}]`);
          if (!r.ok) return r;
        }
      }
      return { ok: true };
    }
    case "string": {
      if (typeof value !== "string") return fail("SCHEMA_TYPE_MISMATCH", `${path} expected string`);
      const fmt = schema.format as string | undefined;
      if (fmt === "email" && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(value)) {
        return fail("SCHEMA_FORMAT_MISMATCH", `${path} is not an email`);
      }
      if (fmt === "date-time" && Number.isNaN(Date.parse(value))) {
        return fail("SCHEMA_FORMAT_MISMATCH", `${path} is not a date-time`);
      }
      return { ok: true };
    }
    case "integer": {
      if (typeof value !== "number" || !Number.isInteger(value)) {
        return fail("SCHEMA_TYPE_MISMATCH", `${path} expected integer`);
      }
      return { ok: true };
    }
    case "number": {
      if (typeof value !== "number") return fail("SCHEMA_TYPE_MISMATCH", `${path} expected number`);
      return { ok: true };
    }
    case "boolean": {
      if (typeof value !== "boolean") return fail("SCHEMA_TYPE_MISMATCH", `${path} expected boolean`);
      return { ok: true };
    }
    default:
      // Fail closed on schema shapes we do not understand.
      return fail("SCHEMA_UNSUPPORTED", `${path} has unsupported schema type ${String(type)}`);
  }
}

function fail(reason_code: string, detail: string): SchemaError {
  return { ok: false, reason_code, detail };
}
