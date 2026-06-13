package sdk

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// HashPrefix is the algorithm prefix on every VCP digest (spec §3 rule 1).
const HashPrefix = "sha256:"

// HashJCS computes the VCP content hash of an already-decoded JSON value v:
// SHA-256 over the JCS canonicalization of v, lowercase hex, prefixed "sha256:".
// This is the single primitive all content-addressing, signing, and binding in
// VCP is built on (spec §3).
func HashJCS(v any) (string, error) {
	canon, err := Canonicalize(v)
	if err != nil {
		return "", err
	}
	return hashBytes(canon), nil
}

// HashJSONBytes decodes raw JSON bytes and returns HashJCS of the result. It is a
// convenience for callers holding wire bytes (e.g. a vector's `value`) rather than
// a decoded structure. Numbers are decoded as float64 (standard library default),
// matching the JCS number rules in this package.
func HashJSONBytes(raw []byte) (string, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", fmt.Errorf("hash: decode: %w", err)
	}
	return HashJCS(v)
}

func hashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return HashPrefix + hex.EncodeToString(sum[:])
}

// DigestHex returns the lowercase hex digest (without the "sha256:" prefix) of a
// VCP hash string, or an error if it is not a well-formed sha256 digest.
func DigestHex(hash string) (string, error) {
	if len(hash) != len(HashPrefix)+64 || hash[:len(HashPrefix)] != HashPrefix {
		return "", fmt.Errorf("hash: %q is not a sha256: digest", hash)
	}
	hexpart := hash[len(HashPrefix):]
	if _, err := hex.DecodeString(hexpart); err != nil {
		return "", fmt.Errorf("hash: %q has non-hex digest", hash)
	}
	return hexpart, nil
}
