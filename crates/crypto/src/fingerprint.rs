use crate::hash::sha256_digest;

pub fn compute_fingerprint(public_key_bytes: &[u8]) -> String {
    format!("SHA256:{}", sha256_digest(public_key_bytes))
}

pub fn compute_colon_fingerprint(public_key_bytes: &[u8]) -> String {
    let hex_str = sha256_digest(public_key_bytes);
    let chunks: Vec<&str> = (0..hex_str.len())
        .step_by(2)
        .map(|i| &hex_str[i..i + 2])
        .collect();
    format!("SHA256:{}", chunks.join(":"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprints() {
        let key_bytes = [0x42u8; 32];
        let fp = compute_fingerprint(&key_bytes);
        assert!(fp.starts_with("SHA256:"));
        assert_eq!(fp.len(), 7 + 64);

        let colon_fp = compute_colon_fingerprint(&key_bytes);
        assert!(colon_fp.starts_with("SHA256:"));
        assert_eq!(colon_fp.matches(':').count(), 32);
    }
}
