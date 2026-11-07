use chrono::Utc;
use uuid::Uuid;
use warm_crypto::{seal_asymmetric_payload, sha256_digest, EvidenceEncryptionKeypair};
use warm_events::EventCategory;
use warm_storage::*;

#[test]
fn test_storage_and_hash_chain_integrity() {
    let store = SqliteAuditStore::open_in_memory().expect("Should open in-memory store");
    let contest_uuid = Uuid::new_v4();
    let participant_id = "contestant-100";
    let session_id = Uuid::new_v4();

    let judge_keypair = EvidenceEncryptionKeypair::generate();
    let mut tracker = HashChainTracker::new(contest_uuid, participant_id);

    for i in 1..=5 {
        let payload = format!("{{\"action\":\"step_{i}\"}}").into_bytes();
        let payload_hash = sha256_digest(&payload);
        let now = Utc::now();
        let timestamp_str = now.to_rfc3339();

        let (seq, prev_hash, current_hash) =
            tracker.step(&timestamp_str, EventCategory::Process, &payload_hash);
        assert_eq!(seq, i);

        let aad = format!("{}:{}:{}", contest_uuid, participant_id, seq).into_bytes();
        let sealed =
            seal_asymmetric_payload(&judge_keypair.public_key, &contest_uuid, &payload, &aad)
                .expect("Sealing should succeed");

        store
            .record_event(
                seq,
                Uuid::new_v4(),
                contest_uuid,
                participant_id,
                session_id,
                now,
                EventCategory::Process,
                &sealed,
                &payload_hash,
                &prev_hash,
                &current_hash,
            )
            .expect("Recording should succeed");
    }

    assert_eq!(store.get_event_count().unwrap(), 5);

    let report = store
        .verify_integrity(&contest_uuid, participant_id)
        .expect("Verification should succeed");

    assert!(report.is_valid);
    assert_eq!(report.total_events, 5);
    assert_eq!(report.first_sequence, Some(1));
    assert_eq!(report.last_sequence, Some(5));
    assert!(report.anomalies.is_empty());
}

#[test]
fn test_storage_crash_recovery_and_resume() {
    let temp_db = std::env::temp_dir().join(format!("warm_recovery_{}.sqlite", Uuid::new_v4()));
    let contest_uuid = Uuid::new_v4();
    let participant_id = "contestant-200";
    let session_id = Uuid::new_v4();
    let judge_keypair = EvidenceEncryptionKeypair::generate();

    {
        let store = SqliteAuditStore::open(&temp_db).expect("Should open DB");
        let mut tracker = HashChainTracker::new(contest_uuid, participant_id);

        for i in 1..=3 {
            let payload = format!("{{\"run\":1,\"step\":{i}}}").into_bytes();
            let payload_hash = sha256_digest(&payload);
            let now = Utc::now();
            let (seq, prev_hash, curr_hash) = tracker.step(
                &now.to_rfc3339(),
                EventCategory::SystemLifecycle,
                &payload_hash,
            );

            let aad = format!("{}:{}:{}", contest_uuid, participant_id, seq).into_bytes();
            let sealed =
                seal_asymmetric_payload(&judge_keypair.public_key, &contest_uuid, &payload, &aad)
                    .unwrap();

            store
                .record_event(
                    seq,
                    Uuid::new_v4(),
                    contest_uuid,
                    participant_id,
                    session_id,
                    now,
                    EventCategory::SystemLifecycle,
                    &sealed,
                    &payload_hash,
                    &prev_hash,
                    &curr_hash,
                )
                .unwrap();
        }
    }

    {
        let store = SqliteAuditStore::open(&temp_db).expect("Should reopen DB");
        assert_eq!(store.get_event_count().unwrap(), 3);

        let (last_seq, last_hash) = store
            .get_latest_event_info()
            .unwrap()
            .expect("Should have latest event");
        assert_eq!(last_seq, 3);

        let mut tracker =
            HashChainTracker::resume(contest_uuid, participant_id, last_seq, last_hash);

        for i in 4..=5 {
            let payload = format!("{{\"run\":2,\"step\":{i}}}").into_bytes();
            let payload_hash = sha256_digest(&payload);
            let now = Utc::now();
            let (seq, prev_hash, curr_hash) =
                tracker.step(&now.to_rfc3339(), EventCategory::Network, &payload_hash);

            let aad = format!("{}:{}:{}", contest_uuid, participant_id, seq).into_bytes();
            let sealed =
                seal_asymmetric_payload(&judge_keypair.public_key, &contest_uuid, &payload, &aad)
                    .unwrap();

            store
                .record_event(
                    seq,
                    Uuid::new_v4(),
                    contest_uuid,
                    participant_id,
                    session_id,
                    now,
                    EventCategory::Network,
                    &sealed,
                    &payload_hash,
                    &prev_hash,
                    &curr_hash,
                )
                .unwrap();
        }

        let report = store
            .verify_integrity(&contest_uuid, participant_id)
            .unwrap();
        assert!(report.is_valid);
        assert_eq!(report.total_events, 5);
        assert_eq!(report.first_sequence, Some(1));
        assert_eq!(report.last_sequence, Some(5));
        assert!(report.anomalies.is_empty());
    }

    let _ = std::fs::remove_file(temp_db);
}
