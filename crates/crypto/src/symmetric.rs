use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;
use warm_core::{Result, WarmError};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

pub const WARM_HKDF_INFO: &[u8] = b"WARM-EVENT-AES-256-GCM";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SealedPayload {
    pub ephemeral_public_key_hex: String,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
}

pub fn derive_symmetric_key(
    shared_secret: &[u8; 32],
    salt: &[u8],
    info: &[u8],
) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .map_err(|e| WarmError::Crypto(format!("HKDF expansion failed: {e}")))?;
    Ok(okm)
}

pub fn aes_gcm_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| WarmError::Crypto(format!("Failed to initialize AES-GCM cipher: {e}")))?;
    let gcm_nonce = Nonce::from_slice(nonce);

    let payload = Payload {
        msg: plaintext,
        aad,
    };

    cipher
        .encrypt(gcm_nonce, payload)
        .map_err(|e| WarmError::Crypto(format!("AES-GCM encryption failed: {e}")))
}

pub fn aes_gcm_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| WarmError::Crypto(format!("Failed to initialize AES-GCM cipher: {e}")))?;
    let gcm_nonce = Nonce::from_slice(nonce);

    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    cipher
        .decrypt(gcm_nonce, payload)
        .map_err(|e| WarmError::Crypto(format!("AES-GCM decryption / authentication failed: {e}")))
}

pub fn seal_asymmetric_payload(
    judge_public_key: &X25519PublicKey,
    contest_uuid: &Uuid,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<SealedPayload> {
    let ephemeral_secret = X25519StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

    let shared_secret = ephemeral_secret.diffie_hellman(judge_public_key).to_bytes();
    let symmetric_key =
        derive_symmetric_key(&shared_secret, contest_uuid.as_bytes(), WARM_HKDF_INFO)?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);

    let ciphertext = aes_gcm_encrypt(&symmetric_key, &nonce_bytes, plaintext, aad)?;

    Ok(SealedPayload {
        ephemeral_public_key_hex: hex::encode(ephemeral_public.as_bytes()),
        nonce_hex: hex::encode(nonce_bytes),
        ciphertext_hex: hex::encode(ciphertext),
    })
}

pub fn open_asymmetric_payload(
    judge_secret_key: &X25519StaticSecret,
    contest_uuid: &Uuid,
    sealed: &SealedPayload,
    aad: &[u8],
) -> Result<Vec<u8>> {
    let ephem_bytes = hex::decode(&sealed.ephemeral_public_key_hex)
        .map_err(|e| WarmError::Crypto(format!("Invalid ephemeral public key hex: {e}")))?;
    if ephem_bytes.len() != 32 {
        return Err(WarmError::Crypto(
            "Ephemeral public key must be 32 bytes".into(),
        ));
    }
    let mut ephem_pk_arr = [0u8; 32];
    ephem_pk_arr.copy_from_slice(&ephem_bytes);
    let ephemeral_public = X25519PublicKey::from(ephem_pk_arr);

    let shared_secret = judge_secret_key
        .diffie_hellman(&ephemeral_public)
        .to_bytes();
    let symmetric_key =
        derive_symmetric_key(&shared_secret, contest_uuid.as_bytes(), WARM_HKDF_INFO)?;

    let nonce_bytes = hex::decode(&sealed.nonce_hex)
        .map_err(|e| WarmError::Crypto(format!("Invalid nonce hex: {e}")))?;
    if nonce_bytes.len() != 12 {
        return Err(WarmError::Crypto("Nonce must be 12 bytes".into()));
    }
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(&nonce_bytes);

    let ciphertext = hex::decode(&sealed.ciphertext_hex)
        .map_err(|e| WarmError::Crypto(format!("Invalid ciphertext hex: {e}")))?;

    aes_gcm_decrypt(&symmetric_key, &nonce_arr, &ciphertext, aad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symmetric_seal_and_open() {
        let judge_secret = X25519StaticSecret::random_from_rng(OsRng);
        let judge_public = X25519PublicKey::from(&judge_secret);
        let contest_uuid = Uuid::new_v4();

        let plaintext = b"Sensitive audit event: process ollama launched at 12:00:00";
        let aad = b"Sequence 42 - Timestamp 2026-11-07T09:30:00Z";

        let sealed = seal_asymmetric_payload(&judge_public, &contest_uuid, plaintext, aad)
            .expect("Sealing should succeed");

        let decrypted = open_asymmetric_payload(&judge_secret, &contest_uuid, &sealed, aad)
            .expect("Decryption should succeed");

        assert_eq!(decrypted, plaintext);

        let tampered_aad = b"Sequence 43 - Tampered AAD";
        let err = open_asymmetric_payload(&judge_secret, &contest_uuid, &sealed, tampered_aad);
        assert!(err.is_err());
    }
}
