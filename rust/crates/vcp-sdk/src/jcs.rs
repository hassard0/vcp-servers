//! JSON Canonicalization Scheme (JCS, RFC 8785) + `sha256:` content hashing.
//!
//! VCP §3: all content-addressing, signing, and binding depend on a single
//! unambiguous serialization. The v0.1 conformance vectors deliberately use
//! only objects, arrays, strings, integers, booleans, and null, so JCS reduces
//! to: sort object keys by UTF-16 code unit, no insignificant whitespace,
//! minimal string escaping, UTF-8 output.
//!
//! We canonicalize a [`serde_json::Value`] ourselves rather than rely on
//! `serde_json::to_string`, because the default serializer does not sort object
//! keys. String escaping and non-ASCII handling (raw UTF-8, not `\u` escapes)
//! match serde_json's compact encoder, which is what the vectors expect.

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Canonicalize a `serde_json::Value` into its RFC 8785 JCS byte string.
pub fn canonicalize_value(value: &Value) -> String {
    let mut out = String::new();
    write_value(value, &mut out);
    out
}

/// Canonicalize any `Serialize` type by first converting it to a
/// `serde_json::Value`, then applying JCS.
pub fn canonicalize<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let v = serde_json::to_value(value)?;
    Ok(canonicalize_value(&v))
}

/// `sha256:<lowercase-hex>` of the JCS bytes of a `Value` (VCP §3).
pub fn hash_value(value: &Value) -> String {
    hash_bytes(canonicalize_value(value).as_bytes())
}

/// `sha256:<lowercase-hex>` of the JCS bytes of any `Serialize` type.
pub fn hash<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    Ok(hash_bytes(canonicalize(value)?.as_bytes()))
}

/// Raw `sha256:` digest of arbitrary bytes.
pub fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut s = String::with_capacity(7 + 64);
    s.push_str("sha256:");
    for b in digest.iter() {
        // lowercase hex, two chars per byte
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

fn write_value(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => write_number(n, out),
        Value::String(s) => write_string(s, out),
        Value::Array(arr) => {
            out.push('[');
            for (i, v) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(v, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            // Sort keys by UTF-16 code unit (RFC 8785 §3.2.3).
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| cmp_utf16(a, b));
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(k, out);
                out.push(':');
                write_value(&map[*k], out);
            }
            out.push('}');
        }
    }
}

/// Compare two strings by their UTF-16 code unit sequences, per RFC 8785.
/// For the BMP this is identical to Unicode code point order; for supplementary
/// characters the surrogate encoding can reorder relative to code points, which
/// is exactly what JCS requires.
fn cmp_utf16(a: &str, b: &str) -> std::cmp::Ordering {
    let mut ai = a.encode_utf16();
    let mut bi = b.encode_utf16();
    loop {
        match (ai.next(), bi.next()) {
            (Some(x), Some(y)) => match x.cmp(&y) {
                std::cmp::Ordering::Equal => continue,
                ord => return ord,
            },
            (Some(_), None) => return std::cmp::Ordering::Greater,
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (None, None) => return std::cmp::Ordering::Equal,
        }
    }
}

fn write_number(n: &serde_json::Number, out: &mut String) {
    // The v0.1 vectors use only integers. Integers have a single canonical
    // serde_json form (no exponent, no fraction), which matches JCS for the
    // integer range. Floats are out of scope for v0.1 (README), but we still
    // emit serde_json's shortest round-trip form rather than panic.
    out.push_str(&n.to_string());
}

/// Serialize a JSON string with the minimal escaping JCS mandates: escape only
/// `"`, `\`, and the C0 controls (U+0000..U+001F), using the short forms where
/// RFC 8785 defines them. All other characters, including non-ASCII, are emitted
/// as raw UTF-8.
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str("\\u");
                let code = c as u32;
                for shift in [12, 8, 4, 0] {
                    let nyb = (code >> shift) & 0xf;
                    out.push(char::from_digit(nyb, 16).unwrap());
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn empty_object() {
        assert_eq!(canonicalize_value(&json!({})), "{}");
        assert_eq!(
            hash_value(&json!({})),
            "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        );
    }

    #[test]
    fn key_order_and_unicode() {
        assert_eq!(
            canonicalize_value(&json!({"b":1,"a":2,"c":3})),
            "{\"a\":2,\"b\":1,\"c\":3}"
        );
        assert_eq!(
            canonicalize_value(&json!({"name":"café","emoji":"✓"})),
            "{\"emoji\":\"✓\",\"name\":\"café\"}"
        );
    }
}
