use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand::Rng;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthCryptoError {
    #[error("Password hashing failed: {0}")]
    HashingError(String),
    #[error("Invalid password hash format: {0}")]
    InvalidHash(String),
}

const CHARSET: &[u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub fn generate_secure_password() -> String {
    let mut rng = rand::thread_rng();
    loop {
        let mut pwd = String::with_capacity(8);
        for _ in 0..8 {
            let idx = rng.gen_range(0..CHARSET.len());
            pwd.push(CHARSET[idx] as char);
        }
        let has_letter = pwd.chars().any(|c| c.is_alphabetic());
        let has_digit = pwd.chars().any(|c| c.is_ascii_digit());
        if has_letter && has_digit && pwd.len() == 8 {
            return pwd;
        }
    }
}

pub fn hash_password(password: &str) -> Result<String, AuthCryptoError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AuthCryptoError::HashingError(e.to_string()))?;
    Ok(password_hash.to_string())
}

pub fn verify_password(candidate: &str, password_hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(password_hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(candidate.as_bytes(), &parsed_hash)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_secure_password_properties() {
        for _ in 0..50 {
            let pwd = generate_secure_password();
            assert_eq!(pwd.len(), 8);
            assert!(pwd.chars().any(|c| c.is_alphabetic()));
            assert!(pwd.chars().any(|c| c.is_ascii_digit()));
        }
    }

    #[test]
    fn test_argon2id_hashing_and_verification() {
        let password = generate_secure_password();
        let hash = hash_password(&password).expect("Hashing should succeed");

        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password(&password, &hash));
        assert!(!verify_password("wrong-password", &hash));
        assert!(!verify_password("", &hash));
    }

    #[test]
    fn test_argon2id_unique_salts() {
        let password = "TestPassword123";
        let hash1 = hash_password(password).unwrap();
        let hash2 = hash_password(password).unwrap();

        assert_ne!(hash1, hash2);
        assert!(verify_password(password, &hash1));
        assert!(verify_password(password, &hash2));
    }
}
