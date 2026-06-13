package sdk

import (
	"crypto/ed25519"
	"testing"
)

// TestStatementAttesterRoundTrip checks the §27.3 statement-tier attester: it
// produces a signed environment statement bound to the challenge nonce, the
// signature verifies over the statement without its signature block, and any
// mutation (including a swapped nonce) breaks verification.
func TestStatementAttesterRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	attester := StatementAttester{
		Signer:          Ed25519Signer{PrivateKey: priv},
		SubjectRole:     RoleProvider,
		Issuer:          "did:web:demo",
		BuildDigest:     "sha256:abababababababababababababababababababababababababababababababab",
		ContainerDigest: "sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
	}
	verifier := Ed25519Verifier{PublicKey: pub}

	stmt, err := attester.Attest("nonce-xyz", 7, "2026-06-13T16:30:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if stmt.Kind != EnvironmentStatementKind {
		t.Errorf("kind = %q, want %q", stmt.Kind, EnvironmentStatementKind)
	}
	if stmt.Tier != TierStatement {
		t.Errorf("tier = %q, want %q", stmt.Tier, TierStatement)
	}
	if stmt.SubjectRole != RoleProvider {
		t.Errorf("subject_role = %q, want %q", stmt.SubjectRole, RoleProvider)
	}
	if stmt.Nonce != "nonce-xyz" || stmt.BootEpoch != 7 {
		t.Errorf("nonce/boot_epoch = %q/%d, want nonce-xyz/7", stmt.Nonce, stmt.BootEpoch)
	}
	if stmt.Signature == nil {
		t.Fatal("statement was not signed")
	}

	ok, err := stmt.VerifyEnvironmentSignature(verifier)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("valid statement signature failed to verify")
	}

	// Tamper: change the nonce after signing ⇒ signature must not verify.
	tampered := stmt
	tampered.Nonce = "nonce-evil"
	ok, err = tampered.VerifyEnvironmentSignature(verifier)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("signature verified over a tampered (re-nonced) statement")
	}

	// A missing signer is rejected.
	if _, err := (StatementAttester{}).Attest("n", 1, "2026-06-13T16:30:00Z"); err == nil {
		t.Error("attester with no signer should error")
	}
	// A missing nonce is rejected (freshness, §27.4).
	if _, err := attester.Attest("", 1, "2026-06-13T16:30:00Z"); err == nil {
		t.Error("attester with empty nonce should error")
	}
}
