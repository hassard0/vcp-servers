//! Signing abstraction (§3). The default algorithm is Ed25519; `alg` is always
//! carried in-band so a verifier never assumes it.

use ed25519_dalek::{Signature as DalekSig, Signer as _, SigningKey, Verifier as _, VerifyingKey};

use crate::jcs;

/// Abstracts over how a document is signed so callers can swap key backends
/// (in-memory, HSM, KMS) without changing the protocol code.
pub trait Signer {
    /// The in-band algorithm identifier, e.g. `"Ed25519"`.
    fn alg(&self) -> &str;
    /// Sign the given bytes, returning the lowercase-hex signature value.
    fn sign(&self, bytes: &[u8]) -> String;
    /// The verifying (public) key bytes, for thumbprint / verification.
    fn public_key_bytes(&self) -> Vec<u8>;
}

/// Verifies a signature produced by a [`Signer`] of a compatible algorithm.
pub trait Verifier {
    fn verify(&self, bytes: &[u8], signature_hex: &str) -> bool;
}

/// An in-memory Ed25519 keypair implementing [`Signer`] and [`Verifier`].
pub struct Ed25519Signer {
    key: SigningKey,
}

impl Ed25519Signer {
    /// Wrap an existing 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(seed),
        }
    }

    /// Deterministic test/dev key from a label. NOT for production keys.
    pub fn from_label(label: &str) -> Self {
        let seed = derive_seed(label);
        Self::from_seed(&seed)
    }

    /// The verifying key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// A DPoP-style JWK thumbprint of the public key (`sha256:` of the raw key
    /// bytes — a stand-in for the full RFC 7638 JWK thumbprint, sufficient for
    /// binding a grant to a holder key in this reference).
    pub fn jkt(&self) -> String {
        jcs::hash_bytes(self.verifying_key().as_bytes())
    }
}

impl Signer for Ed25519Signer {
    fn alg(&self) -> &str {
        "Ed25519"
    }
    fn sign(&self, bytes: &[u8]) -> String {
        let sig: DalekSig = self.key.sign(bytes);
        hex(&sig.to_bytes())
    }
    fn public_key_bytes(&self) -> Vec<u8> {
        self.verifying_key().as_bytes().to_vec()
    }
}

/// Verify an Ed25519 signature given the public key bytes.
pub struct Ed25519Verifier {
    key: VerifyingKey,
}

impl Ed25519Verifier {
    pub fn from_public_bytes(bytes: &[u8]) -> Option<Self> {
        let arr: [u8; 32] = bytes.try_into().ok()?;
        VerifyingKey::from_bytes(&arr).ok().map(|key| Self { key })
    }
    pub fn from_signer(signer: &Ed25519Signer) -> Self {
        Self {
            key: signer.verifying_key(),
        }
    }
}

impl Verifier for Ed25519Verifier {
    fn verify(&self, bytes: &[u8], signature_hex: &str) -> bool {
        let raw = match unhex(signature_hex) {
            Some(r) => r,
            None => return false,
        };
        let arr: [u8; 64] = match raw.try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };
        let sig = DalekSig::from_bytes(&arr);
        self.key.verify(bytes, &sig).is_ok()
    }
}

fn derive_seed(label: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"vcp-dev-seed:");
    h.update(label.as_bytes());
    let d = h.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&d);
    seed
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let signer = Ed25519Signer::from_label("test");
        let msg = b"hello vcp";
        let sig = signer.sign(msg);
        let verifier = Ed25519Verifier::from_signer(&signer);
        assert!(verifier.verify(msg, &sig));
        assert!(!verifier.verify(b"tampered", &sig));
    }
}
