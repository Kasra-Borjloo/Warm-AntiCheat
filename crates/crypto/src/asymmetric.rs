use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use warm_core::{Result, WarmError};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

/// Ed25519 key pair for digital signing (e.g. contest manifests, tokens).
pub struct ManifestSigningKeypair {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

impl ManifestSigningKeypair {
    /// Generate a cryptographically secure random Ed25519 key pair using OsRng.
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Load from a 32-byte private key seed.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(bytes);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Sign an arbitrary message, returning a 64-byte Ed25519 signature.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    /// Sign and return hex-encoded signature string.
    pub fn sign_hex(&self, message: &[u8]) -> String {
        hex::encode(self.sign(message).to_bytes())
    }

    pub fn private_key_hex(&self) -> String {
        hex::encode(self.signing_key.to_bytes())
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.verifying_key.to_bytes())
    }
}

/// Verify an Ed25519 signature given the raw public key bytes.
pub fn verify_signature(
    public_key_bytes: &[u8; 32],
    message: &[u8],
    signature_bytes: &[u8; 64],
) -> Result<()> {
    let verifying_key = VerifyingKey::from_bytes(public_key_bytes)
        .map_err(|e| WarmError::Crypto(format!("Invalid Ed25519 public key: {e}")))?;
    let signature = Signature::from_bytes(signature_bytes);

    verifying_key
        .verify(message, &signature)
        .map_err(|e| WarmError::Verification(format!("Signature verification failed: {e}")))
}

/// Verify an Ed25519 signature from hex-encoded public key and signature.
pub fn verify_signature_hex(
    public_key_hex: &str,
    message: &[u8],
    signature_hex: &str,
) -> Result<()> {
    let pub_bytes = hex::decode(public_key_hex.trim())
        .map_err(|e| WarmError::Crypto(format!("Invalid public key hex: {e}")))?;
    if pub_bytes.len() != 32 {
        return Err(WarmError::Crypto("Public key must be 32 bytes".into()));
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&pub_bytes);

    let sig_bytes = hex::decode(signature_hex.trim())
        .map_err(|e| WarmError::Crypto(format!("Invalid signature hex: {e}")))?;
    if sig_bytes.len() != 64 {
        return Err(WarmError::Crypto("Signature must be 64 bytes".into()));
    }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&sig_bytes);

    verify_signature(&pk, message, &sig)
}

/// Key pair for asymmetric audit encryption and decryption using X25519 Diffie-Hellman.
pub struct EvidenceEncryptionKeypair {
    pub secret_key: X25519StaticSecret,
    pub public_key: X25519PublicKey,
}

impl EvidenceEncryptionKeypair {
    /// Generate a fresh X25519 static keypair.
    pub fn generate() -> Self {
        let secret_key = X25519StaticSecret::random_from_rng(OsRng);
        let public_key = X25519PublicKey::from(&secret_key);
        Self {
            secret_key,
            public_key,
        }
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        let secret_key = X25519StaticSecret::from(bytes);
        let public_key = X25519PublicKey::from(&secret_key);
        Self {
            secret_key,
            public_key,
        }
    }

    /// Perform Diffie-Hellman key exchange with a peer's public key to compute a 32-byte shared secret.
    pub fn diffie_hellman(&self, peer_public: &X25519PublicKey) -> [u8; 32] {
        self.secret_key.diffie_hellman(peer_public).to_bytes()
    }

    pub fn private_key_hex(&self) -> String {
        hex::encode(self.secret_key.to_bytes())
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_sign_and_verify() {
        let keypair = ManifestSigningKeypair::generate();
        let message = b"GOCUP-1:MANIFEST:CONTEST_DEFINITION";

        let sig = keypair.sign(message);
        assert!(
            verify_signature(keypair.verifying_key.as_bytes(), message, &sig.to_bytes()).is_ok()
        );

        let sig_hex = keypair.sign_hex(message);
        assert!(verify_signature_hex(&keypair.public_key_hex(), message, &sig_hex).is_ok());

        // Tampered message should fail
        assert!(verify_signature_hex(&keypair.public_key_hex(), b"TAMPERED", &sig_hex).is_err());
    }

    #[test]
    fn test_x25519_diffie_hellman() {
        let alice = EvidenceEncryptionKeypair::generate();
        let bob = EvidenceEncryptionKeypair::generate();

        let shared_alice = alice.diffie_hellman(&bob.public_key);
        let shared_bob = bob.diffie_hellman(&alice.public_key);

        assert_eq!(shared_alice, shared_bob);
    }
}
