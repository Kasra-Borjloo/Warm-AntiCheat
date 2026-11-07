use uuid::Uuid;
use warm_crypto::*;

#[test]
fn test_end_to_end_crypto_pipeline() {
    // 1. Organizer generates Ed25519 signing keypair for Contest Manifest
    let manifest_keypair = ManifestSigningKeypair::generate();
    let manifest_content = br#"{"contest_title":"GOCUP 1","version":"1.0"}"#;

    let signature_hex = manifest_keypair.sign_hex(manifest_content);
    assert!(verify_signature_hex(
        &manifest_keypair.public_key_hex(),
        manifest_content,
        &signature_hex
    )
    .is_ok());

    // 2. Organizer generates X25519 evidence keypair for Judge decryption
    let judge_keypair = EvidenceEncryptionKeypair::generate();
    let judge_public_key = judge_keypair.public_key;

    // 3. Participant client seals an audit event payload using Judge Public Key
    let contest_uuid = Uuid::new_v4();
    let participant_id = "contestant-99";
    let event_payload = br#"{"action":"process_spawn","exe":"code.exe","pid":1234}"#;
    let aad = format!("{}:{}:0", contest_uuid, participant_id).into_bytes();

    let sealed = seal_asymmetric_payload(&judge_public_key, &contest_uuid, event_payload, &aad)
        .expect("Payload sealing should succeed");

    // 4. Participant cannot decrypt without Judge Secret Key
    // Judge receives sealed payload and decrypts with Judge Secret Key
    let decrypted =
        open_asymmetric_payload(&judge_keypair.secret_key, &contest_uuid, &sealed, &aad)
            .expect("Judge decryption should succeed");

    assert_eq!(decrypted, event_payload);

    // 5. Hash Chain Verification
    let h0 = compute_genesis_hash(&contest_uuid, participant_id);
    let payload_hash = sha256_digest(event_payload);
    let h1 = compute_event_hash(1, "2026-11-07T09:30:00Z", &h0, "Process", &payload_hash);

    assert!(verify_event_hash(
        &h1,
        1,
        "2026-11-07T09:30:00Z",
        &h0,
        "Process",
        &payload_hash
    ));

    // 6. Key Fingerprints
    let fp = compute_fingerprint(judge_public_key.as_bytes());
    assert!(fp.starts_with("SHA256:"));
}

#[test]
fn test_tamper_detection_in_crypto() {
    let judge_keypair = EvidenceEncryptionKeypair::generate();
    let contest_uuid = Uuid::new_v4();
    let payload = b"Original un-tampered data";
    let aad = b"Context-Seq-1";

    let mut sealed =
        seal_asymmetric_payload(&judge_keypair.public_key, &contest_uuid, payload, aad)
            .expect("Should seal");

    // Alter one byte of the ciphertext
    let mut raw_ct = hex::decode(&sealed.ciphertext_hex).unwrap();
    raw_ct[0] ^= 0xFF;
    sealed.ciphertext_hex = hex::encode(raw_ct);

    // Decryption must fail due to GCM authentication tag mismatch
    let result = open_asymmetric_payload(&judge_keypair.secret_key, &contest_uuid, &sealed, aad);
    assert!(result.is_err());
}
