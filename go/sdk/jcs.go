// Package sdk is the lightweight VCP (Verifiable Capability Protocol) client/SDK.
//
// It implements the canonicalization, hashing, identity, signing, planning, and
// MCP-bridge primitives a Host/Planner side needs. The heavy enforcing logic
// (policy, grants, taint, invocation) lives in the sibling gateway package.
//
// Everything in this package targets only the Go standard library.
package sdk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// Canonicalize returns the JSON Canonicalization Scheme (RFC 8785) serialization
// of v, where v is a value as produced by json.Unmarshal into an any: that is one
// of map[string]any, []any, string, float64, bool, or nil.
//
// Go's encoding/json is deliberately NOT used for the structural emission because:
//   - it does not sort nested object keys by UTF-16 code unit, and
//   - it HTML-escapes <, >, & by default.
//
// This function emits canonical bytes directly: object keys sorted by UTF-16 code
// unit, no insignificant whitespace, RFC 8785 string escaping (no HTML escaping),
// and RFC 8785 / ECMAScript number formatting. Because VCP v0.1 vectors use only
// integers, whole-valued float64 numbers are emitted without a decimal point.
func Canonicalize(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := canonicalizeValue(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func canonicalizeValue(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		writeCanonicalString(buf, t)
	case float64:
		s, err := canonicalNumber(t)
		if err != nil {
			return err
		}
		buf.WriteString(s)
	case int:
		buf.WriteString(strconv.Itoa(t))
	case int64:
		buf.WriteString(strconv.FormatInt(t, 10))
	case json.Number:
		// json.Number arrives when callers decode with UseNumber(); treat the
		// textual form as authoritative if it is a valid JSON number.
		buf.WriteString(string(t))
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := canonicalizeValue(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		return canonicalizeObject(buf, t)
	default:
		return fmt.Errorf("jcs: unsupported type %T", v)
	}
	return nil
}

func canonicalizeObject(buf *bytes.Buffer, m map[string]any) error {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return lessUTF16(keys[i], keys[j])
	})
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		writeCanonicalString(buf, k)
		buf.WriteByte(':')
		if err := canonicalizeValue(buf, m[k]); err != nil {
			return err
		}
	}
	buf.WriteByte('}')
	return nil
}

// lessUTF16 reports whether a sorts before b when both are compared as sequences
// of UTF-16 code units, which is the ordering RFC 8785 mandates for object keys.
//
// For Basic Multilingual Plane characters this is identical to Unicode code point
// order; it only diverges for astral characters (which encode as surrogate pairs
// whose lead unit, 0xD800-0xDBFF, sorts below code points 0xE000-0xFFFF). Encoding
// to UTF-16 and comparing the resulting code-unit slices handles both cases.
func lessUTF16(a, b string) bool {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	n := len(ua)
	if len(ub) < n {
		n = len(ub)
	}
	for i := 0; i < n; i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// writeCanonicalString writes s as a JCS (RFC 8785 §3.2.2.2) JSON string literal.
//
// The escape set is the minimal one required by RFC 8785: the two-character
// escapes for ", \, backspace, form feed, newline, carriage return, and tab; a
// \u00xx escape for every other control character below U+0020; and otherwise the
// raw UTF-8 bytes of the character. Crucially, <, >, and & are NOT escaped (unlike
// encoding/json's default), and non-ASCII characters are emitted as literal UTF-8.
func writeCanonicalString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				// Other C0 control characters: \u00xx, lowercase hex.
				buf.WriteString(`\u00`)
				const hexdigits = "0123456789abcdef"
				buf.WriteByte(hexdigits[(r>>4)&0xF])
				buf.WriteByte(hexdigits[r&0xF])
				continue
			}
			if r == utf8.RuneError {
				// Preserve replacement char as its UTF-8 encoding.
				buf.WriteRune(r)
				continue
			}
			buf.WriteRune(r)
		}
	}
	buf.WriteByte('"')
}

// canonicalNumber formats a float64 per RFC 8785 §3.2.2.3 (ECMAScript Number::
// toString) for the integer subset VCP v0.1 uses, and rejects values JSON cannot
// represent. Whole numbers are emitted with no decimal point or exponent (e.g.
// 42, not 42.0 or 4.2e1). Non-integer values are formatted with the shortest
// round-tripping decimal (strconv 'g'); this is sufficient because the conformance
// vectors deliberately avoid fractional numbers.
func canonicalNumber(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", fmt.Errorf("jcs: %v is not representable in JSON", f)
	}
	if f == math.Trunc(f) && math.Abs(f) < 1e21 {
		// Integer-valued: emit without a decimal point. Use FormatFloat with -1
		// precision and 'f' so e.g. 1e6 becomes "1000000". Guard the -0 case so
		// it serializes as "0" per ECMAScript.
		if f == 0 {
			return "0", nil
		}
		return strconv.FormatFloat(f, 'f', -1, 64), nil
	}
	return strconv.FormatFloat(f, 'g', -1, 64), nil
}
