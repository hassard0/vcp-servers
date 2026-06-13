package sdk

import (
	"crypto/ed25519"
	"testing"
)

// TestSignVerifyRoundTrip checks the Ed25519 sign/verify path over canonical
// bytes, including the in-band algorithm check (a verifier with a different alg
// must fail closed).
func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer := Ed25519Signer{PrivateKey: priv}
	verifier := Ed25519Verifier{PublicKey: pub}

	value := map[string]any{"b": 1.0, "a": "x", "nested": map[string]any{"z": true}}
	sig, err := SignValue(signer, value)
	if err != nil {
		t.Fatal(err)
	}
	if sig.Alg != "Ed25519" {
		t.Errorf("alg = %q, want Ed25519", sig.Alg)
	}
	ok, err := VerifyValue(verifier, value, sig)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("valid signature failed to verify")
	}

	// Tampered value must not verify.
	tampered := map[string]any{"b": 2.0, "a": "x", "nested": map[string]any{"z": true}}
	ok, err = VerifyValue(verifier, tampered, sig)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("signature verified over tampered value")
	}

	// Algorithm mismatch must fail closed.
	badAlg := sig
	badAlg.Alg = "RS256"
	ok, _ = VerifyValue(verifier, value, badAlg)
	if ok {
		t.Error("verification accepted a mismatched algorithm")
	}
}

// TestManifestSignIdentity checks that signing a manifest fills a consistent
// identity (id == vcp:cap:name@contract_hash) and that the signature verifies over
// the manifest without its signature block.
func TestManifestSignIdentity(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer := Ed25519Signer{PrivateKey: priv}
	verifier := Ed25519Verifier{PublicKey: pub}

	cap := Capability{
		Name:         "demo.tool",
		Version:      "1.0.0",
		InputSchema:  map[string]any{"type": "object", "additionalProperties": false},
		OutputSchema: map[string]any{"type": "object"},
		Effects:      map[string]any{"class": "read-only", "external_side_effect": false},
		Determinism:  map[string]any{"class": "pure"},
		Sandbox:      map[string]any{"filesystem": "none", "network": []any{}, "secrets": []any{}},
	}
	m := NewManifest("did:web:demo", "demo", cap)
	if err := m.Sign(signer); err != nil {
		t.Fatal(err)
	}
	if m.Capability.ID == "" || m.Capability.ContractHash == "" {
		t.Fatal("identity not populated after Sign")
	}
	want := "vcp:cap:demo.tool@" + m.Capability.ContractHash
	if m.Capability.ID != want {
		t.Errorf("id = %q, want %q", m.Capability.ID, want)
	}

	unsigned, err := m.canonicalValueWithoutSignature()
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyValue(verifier, unsigned, *m.Signature)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("manifest signature did not verify")
	}
}
