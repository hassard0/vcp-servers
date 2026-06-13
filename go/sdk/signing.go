package sdk

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Signer abstracts the production of a detached signature over canonical bytes.
// The default implementation is Ed25519 (spec §3 rule 4); the interface lets a
// Gateway swap in an HSM-backed signer without touching call sites.
type Signer interface {
	// Sign returns a detached signature over the supplied canonical message bytes.
	Sign(message []byte) ([]byte, error)
	// Algorithm returns the in-band `alg` value (e.g. "Ed25519") that MUST travel
	// with the signature; spec §3 forbids assuming the algorithm.
	Algorithm() string
}

// Verifier abstracts signature verification.
type Verifier interface {
	Verify(message, signature []byte) bool
	Algorithm() string
}

// Ed25519Signer signs canonical bytes with an Ed25519 private key.
type Ed25519Signer struct {
	PrivateKey ed25519.PrivateKey
}

// Sign returns the Ed25519 signature over message, or an error if the key size is
// wrong. It implements Signer.
func (s Ed25519Signer) Sign(message []byte) ([]byte, error) {
	if len(s.PrivateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("signing: invalid Ed25519 private key size %d", len(s.PrivateKey))
	}
	return ed25519.Sign(s.PrivateKey, message), nil
}

// Algorithm reports the in-band algorithm identifier "Ed25519". It implements Signer.
func (s Ed25519Signer) Algorithm() string { return "Ed25519" }

// Ed25519Verifier verifies Ed25519 signatures against a public key.
type Ed25519Verifier struct {
	PublicKey ed25519.PublicKey
}

// Verify reports whether signature is a valid Ed25519 signature over message. A
// wrong-sized public key returns false (fail closed). It implements Verifier.
func (v Ed25519Verifier) Verify(message, signature []byte) bool {
	if len(v.PublicKey) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(v.PublicKey, message, signature)
}

// Algorithm reports the in-band algorithm identifier "Ed25519". It implements Verifier.
func (v Ed25519Verifier) Algorithm() string { return "Ed25519" }

// Signature is the in-band signature block carried by manifests, grants,
// attestations, and audit events (schemas/*.json). `value` is base64 (std).
type Signature struct {
	Alg   string `json:"alg"`
	Value string `json:"value"`
}

// SignValue canonicalizes a JSON value (which MUST already have any embedded
// signature block removed, per spec §3 rule 4) and signs the canonical bytes.
func SignValue(s Signer, valueWithoutSignature any) (Signature, error) {
	canon, err := Canonicalize(valueWithoutSignature)
	if err != nil {
		return Signature{}, err
	}
	sig, err := s.Sign(canon)
	if err != nil {
		return Signature{}, err
	}
	return Signature{Alg: s.Algorithm(), Value: base64.StdEncoding.EncodeToString(sig)}, nil
}

// VerifyValue verifies sig over the canonicalization of valueWithoutSignature.
// The signature `alg` MUST match the verifier's algorithm (spec §3: alg is carried
// in-band and never assumed). A bad base64 value, an algorithm mismatch, or a
// failed cryptographic check all return false (fail closed).
func VerifyValue(v Verifier, valueWithoutSignature any, sig Signature) (bool, error) {
	if sig.Alg != v.Algorithm() {
		return false, nil
	}
	raw, err := base64.StdEncoding.DecodeString(sig.Value)
	if err != nil {
		return false, nil
	}
	canon, err := Canonicalize(valueWithoutSignature)
	if err != nil {
		return false, err
	}
	return v.Verify(canon, raw), nil
}

// stripKey returns a shallow copy of m without the named key. Used to remove a
// signature block before canonicalization (spec §3 rule 4) without mutating the
// caller's map.
func stripKey(m map[string]any, key string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		if k == key {
			continue
		}
		out[k] = v
	}
	return out
}

// decodeToMap round-trips any JSON-serializable value through encoding/json into a
// map[string]any so it can be canonicalized with consistent (float64) number
// typing. This is the bridge between typed structs and the JCS layer, and it
// guarantees that signing a struct and verifying a decoded wire object agree.
func decodeToMap(v any) (map[string]any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}
