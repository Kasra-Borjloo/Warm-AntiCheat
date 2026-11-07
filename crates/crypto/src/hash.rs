use sha2::{Digest, Sha256};
use uuid::Uuid;

pub fn sha256_digest(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

pub fn compute_genesis_hash(contest_uuid: &Uuid, participant_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"WARM-GENESIS-CHAIN:");
    hasher.update(contest_uuid.as_bytes());
    hasher.update(b":");
    hasher.update(participant_id.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn compute_event_hash(
    seq: u64,
    timestamp_rfc3339: &str,
    prev_hash: &str,
    category: &str,
    payload_hash: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(seq.to_be_bytes());
    hasher.update(b"|");
    hasher.update(timestamp_rfc3339.as_bytes());
    hasher.update(b"|");
    hasher.update(prev_hash.as_bytes());
    hasher.update(b"|");
    hasher.update(category.as_bytes());
    hasher.update(b"|");
    hasher.update(payload_hash.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn verify_event_hash(
    expected_hash: &str,
    seq: u64,
    timestamp_rfc3339: &str,
    prev_hash: &str,
    category: &str,
    payload_hash: &str,
) -> bool {
    let computed = compute_event_hash(seq, timestamp_rfc3339, prev_hash, category, payload_hash);
    computed.eq_ignore_ascii_case(expected_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_digest() {
        assert_eq!(
            sha256_digest(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_hash_chain_continuity() {
        let contest_uuid = Uuid::new_v4();
        let participant_id = "user-101";

        let h0 = compute_genesis_hash(&contest_uuid, participant_id);
        assert_eq!(h0.len(), 64);

        let p1_hash = sha256_digest(b"{\"event\":\"app_launch\"}");
        let h1 = compute_event_hash(1, "2026-11-07T09:00:00Z", &h0, "Lifecycle", &p1_hash);

        assert!(verify_event_hash(
            &h1,
            1,
            "2026-11-07T09:00:00Z",
            &h0,
            "Lifecycle",
            &p1_hash
        ));

        assert!(!verify_event_hash(
            &h1,
            1,
            "2026-11-07T09:00:00Z",
            "tampered_h0",
            "Lifecycle",
            &p1_hash
        ));
    }
}
