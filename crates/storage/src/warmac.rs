use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use tar::{Archive, Builder, Header};
use uuid::Uuid;
use warm_core::{Result, WarmError};
use warm_crypto::{
    aes_gcm_decrypt, aes_gcm_encrypt, derive_symmetric_key, sha256_digest, X25519PublicKey,
    X25519StaticSecret,
};

pub const WARMAC_MAGIC: &[u8; 8] = b"WARMAC01";
pub const WARMAC_HKDF_INFO: &[u8] = b"WARM-WARMAC-AES-256-GCM";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WarmacManifestEntry {
    pub manifest_signature_hex: String,
    pub manifest_signing_key_pub_hex: String,
    pub judge_public_key_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WarmacSessionMetadata {
    pub session_id: Uuid,
    pub contest_uuid: Uuid,
    pub participant_id: String,
    pub total_events: u64,
    pub genesis_hash: String,
    pub final_hash: String,
    pub exported_at: DateTime<Utc>,
    pub authenticated_account_id: Option<Uuid>,
    #[serde(default)]
    pub start_time: Option<DateTime<Utc>>,
    #[serde(default)]
    pub end_time: Option<DateTime<Utc>>,
    #[serde(default)]
    pub file_tamper_count: u64,
    #[serde(default)]
    pub file_tamper_attempts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WarmacAuditChainEntry {
    pub sequence_number: u64,
    pub timestamp_rfc3339: String,
    pub category: String,
    pub previous_event_hash: String,
    pub current_event_hash: String,
}

pub struct DecryptedWarmacArchive {
    pub contest_uuid: Uuid,
    pub session_id: Uuid,
    pub participant_id: String,
    pub files: BTreeMap<String, Vec<u8>>,
    pub file_hashes: BTreeMap<String, String>,
    pub metadata: WarmacSessionMetadata,
    pub raw_tar_bytes: Vec<u8>,
}

impl DecryptedWarmacArchive {
    pub fn get_file(&self, path: &str) -> Option<&[u8]> {
        self.files.get(path).map(|v| v.as_slice())
    }

    pub fn get_file_str(&self, path: &str) -> Option<String> {
        self.files
            .get(path)
            .and_then(|v| String::from_utf8(v.clone()).ok())
    }

    pub fn extract_all_to(&self, destination_dir: &Path) -> Result<()> {
        fs::create_dir_all(destination_dir).map_err(|e| WarmError::Io(e.to_string()))?;
        for (rel_path, content) in &self.files {
            let out_file = destination_dir.join(rel_path);
            if let Some(parent) = out_file.parent() {
                fs::create_dir_all(parent).map_err(|e| WarmError::Io(e.to_string()))?;
            }
            fs::write(&out_file, content).map_err(|e| WarmError::Io(e.to_string()))?;
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub fn create_warmac_package(
    output_path: &Path,
    contest_manifest_json: &[u8],
    manifest_signature_hex: &str,
    manifest_signing_key_pub_hex: &str,
    judge_public_key: &X25519PublicKey,
    store: &crate::SqliteAuditStore,
    contest_uuid: Uuid,
    participant_id: &str,
    session_id: Uuid,
    authenticated_account_id: Option<Uuid>,
    attachments: &[(String, Vec<u8>)],
    start_time: Option<DateTime<Utc>>,
    end_time: Option<DateTime<Utc>>,
    file_tamper_attempts: &[String],
) -> Result<PathBuf> {
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();

    files.insert(
        "manifest/contest.json".to_string(),
        contest_manifest_json.to_vec(),
    );

    let sig_entry = WarmacManifestEntry {
        manifest_signature_hex: manifest_signature_hex.to_string(),
        manifest_signing_key_pub_hex: manifest_signing_key_pub_hex.to_string(),
        judge_public_key_hex: hex::encode(judge_public_key.as_bytes()),
    };
    files.insert(
        "manifest/signatures.json".to_string(),
        serde_json::to_vec_pretty(&sig_entry)
            .map_err(|e| WarmError::Serialization(e.to_string()))?,
    );

    let raw_events = store.get_all_events()?;
    let mut events_jsonl = Vec::new();
    let mut chain_entries = Vec::new();
    let mut process_count = 0u64;
    let mut network_count = 0u64;
    let mut compiler_count = 0u64;

    for ev in &raw_events {
        match ev.category.as_str() {
            "Process" => process_count += 1,
            "Network" => network_count += 1,
            "Compiler" => compiler_count += 1,
            _ => {}
        }

        let ev_obj = serde_json::json!({
            "sequence_number": ev.sequence_number,
            "event_uuid": ev.event_uuid,
            "contest_uuid": ev.contest_uuid,
            "participant_id": ev.participant_id,
            "session_id": ev.session_id,
            "timestamp": ev.timestamp_rfc3339,
            "category": ev.category,
            "payload_hash": ev.payload_hash,
            "previous_event_hash": ev.previous_event_hash,
            "current_event_hash": ev.current_event_hash,
            "sealed_payload": {
                "ephemeral_public_key_hex": ev.sealed_payload.ephemeral_public_key_hex,
                "nonce_hex": ev.sealed_payload.nonce_hex,
                "ciphertext_hex": ev.sealed_payload.ciphertext_hex
            }
        });

        let line =
            serde_json::to_string(&ev_obj).map_err(|e| WarmError::Serialization(e.to_string()))?;
        events_jsonl.extend_from_slice(line.as_bytes());
        events_jsonl.push(b'\n');

        chain_entries.push(WarmacAuditChainEntry {
            sequence_number: ev.sequence_number,
            timestamp_rfc3339: ev.timestamp_rfc3339.clone(),
            category: ev.category.clone(),
            previous_event_hash: ev.previous_event_hash.clone(),
            current_event_hash: ev.current_event_hash.clone(),
        });
    }

    files.insert(
        format!("sessions/{}/events.jsonl", session_id),
        events_jsonl,
    );

    let (_last_seq, last_h) = store.get_latest_event_info()?.unwrap_or((0, String::new()));
    let genesis_h = warm_crypto::compute_genesis_hash(&contest_uuid, participant_id);

    let session_meta = WarmacSessionMetadata {
        session_id,
        contest_uuid,
        participant_id: participant_id.to_string(),
        total_events: raw_events.len() as u64,
        genesis_hash: genesis_h,
        final_hash: last_h,
        exported_at: Utc::now(),
        authenticated_account_id,
        start_time,
        end_time,
        file_tamper_count: file_tamper_attempts.len() as u64,
        file_tamper_attempts: file_tamper_attempts.to_vec(),
    };

    files.insert(
        format!("sessions/{}/metadata.json", session_id),
        serde_json::to_vec_pretty(&session_meta)
            .map_err(|e| WarmError::Serialization(e.to_string()))?,
    );

    let proc_summary = serde_json::json!({
        "total_process_events": process_count,
        "recorded_at": Utc::now()
    });
    files.insert(
        format!("sessions/{}/processes/summary.json", session_id),
        serde_json::to_vec_pretty(&proc_summary)
            .map_err(|e| WarmError::Serialization(e.to_string()))?,
    );

    let net_summary = serde_json::json!({
        "total_network_events": network_count,
        "recorded_at": Utc::now()
    });
    files.insert(
        format!("sessions/{}/network/summary.json", session_id),
        serde_json::to_vec_pretty(&net_summary)
            .map_err(|e| WarmError::Serialization(e.to_string()))?,
    );

    let comp_summary = serde_json::json!({
        "total_compiler_events": compiler_count,
        "recorded_at": Utc::now()
    });
    files.insert(
        format!("sessions/{}/compiler/summary.json", session_id),
        serde_json::to_vec_pretty(&comp_summary)
            .map_err(|e| WarmError::Serialization(e.to_string()))?,
    );

    for (name, content) in attachments {
        files.insert(
            format!("sessions/{}/screenshots/{}", session_id, name),
            content.clone(),
        );
    }

    files.insert(
        "integrity/audit-chain.json".to_string(),
        serde_json::to_vec_pretty(&chain_entries)
            .map_err(|e| WarmError::Serialization(e.to_string()))?,
    );

    let mut file_hashes = BTreeMap::new();
    for (path, content) in &files {
        file_hashes.insert(path.clone(), sha256_digest(content));
    }
    let file_hashes_bytes = serde_json::to_vec_pretty(&file_hashes)
        .map_err(|e| WarmError::Serialization(e.to_string()))?;
    files.insert("integrity/file-hashes.json".to_string(), file_hashes_bytes);

    let mut tar_builder = Builder::new(Vec::new());
    for (path, content) in &files {
        let mut header = Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(Utc::now().timestamp() as u64);
        header.set_cksum();
        tar_builder
            .append_data(&mut header, path, Cursor::new(content))
            .map_err(|e| WarmError::Storage(format!("TAR packing error: {e}")))?;
    }
    tar_builder
        .finish()
        .map_err(|e| WarmError::Storage(format!("TAR finalize error: {e}")))?;
    let tar_bytes = tar_builder
        .into_inner()
        .map_err(|e| WarmError::Storage(format!("TAR bytes error: {e}")))?;

    let ephemeral_secret = X25519StaticSecret::random_from_rng(rand::rngs::OsRng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
    let shared_secret = ephemeral_secret.diffie_hellman(judge_public_key).to_bytes();
    let symmetric_key =
        derive_symmetric_key(&shared_secret, contest_uuid.as_bytes(), WARMAC_HKDF_INFO)?;

    let mut nonce = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);

    let aad = format!(
        "WARMAC-V1:{}:{}:{}",
        contest_uuid, participant_id, session_id
    )
    .into_bytes();
    let ciphertext = aes_gcm_encrypt(&symmetric_key, &nonce, &tar_bytes, &aad)?;

    let pid_bytes = participant_id.as_bytes();
    let mut container = Vec::with_capacity(86 + pid_bytes.len() + ciphertext.len());
    container.extend_from_slice(WARMAC_MAGIC);
    container.extend_from_slice(contest_uuid.as_bytes());
    container.extend_from_slice(session_id.as_bytes());
    container.extend_from_slice(&(pid_bytes.len() as u16).to_le_bytes());
    container.extend_from_slice(pid_bytes);
    container.extend_from_slice(ephemeral_public.as_bytes());
    container.extend_from_slice(&nonce);
    container.extend_from_slice(&ciphertext);

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).map_err(|e| WarmError::Io(e.to_string()))?;
    }

    let tmp_path = output_path.with_extension("warmac.tmp");
    fs::write(&tmp_path, &container).map_err(|e| WarmError::Io(e.to_string()))?;
    if output_path.exists() {
        let _ = fs::remove_file(output_path);
    }
    if fs::rename(&tmp_path, output_path).is_err() {
        let _ = fs::copy(&tmp_path, output_path);
        let _ = fs::remove_file(&tmp_path);
    }

    Ok(output_path.to_path_buf())
}

pub fn unpack_warmac_package(
    warmac_bytes: &[u8],
    judge_secret: &X25519StaticSecret,
) -> Result<DecryptedWarmacArchive> {
    if warmac_bytes.len() < 86 {
        return Err(WarmError::Storage(
            "Warmac archive file is too small to be valid".into(),
        ));
    }

    if &warmac_bytes[0..8] != WARMAC_MAGIC {
        return Err(WarmError::Storage(
            "Invalid Warmac archive magic header".into(),
        ));
    }

    let contest_uuid = Uuid::from_slice(&warmac_bytes[8..24])
        .map_err(|e| WarmError::Storage(format!("Invalid contest UUID: {e}")))?;
    let session_id = Uuid::from_slice(&warmac_bytes[24..40])
        .map_err(|e| WarmError::Storage(format!("Invalid session UUID: {e}")))?;

    let pid_len = u16::from_le_bytes([warmac_bytes[40], warmac_bytes[41]]) as usize;
    let pid_end = 42 + pid_len;
    if warmac_bytes.len() < pid_end + 32 + 12 {
        return Err(WarmError::Storage(
            "Malformed Warmac archive header length".into(),
        ));
    }

    let participant_id = String::from_utf8(warmac_bytes[42..pid_end].to_vec())
        .map_err(|e| WarmError::Storage(format!("Invalid participant ID string: {e}")))?;

    let mut ephem_arr = [0u8; 32];
    ephem_arr.copy_from_slice(&warmac_bytes[pid_end..pid_end + 32]);
    let ephemeral_public = X25519PublicKey::from(ephem_arr);

    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&warmac_bytes[pid_end + 32..pid_end + 44]);

    let ciphertext = &warmac_bytes[pid_end + 44..];

    let shared_secret = judge_secret.diffie_hellman(&ephemeral_public).to_bytes();
    let symmetric_key =
        derive_symmetric_key(&shared_secret, contest_uuid.as_bytes(), WARMAC_HKDF_INFO)?;

    let aad = format!(
        "WARMAC-V1:{}:{}:{}",
        contest_uuid, participant_id, session_id
    )
    .into_bytes();
    let tar_bytes = aes_gcm_decrypt(&symmetric_key, &nonce, ciphertext, &aad)?;

    let mut archive = Archive::new(Cursor::new(&tar_bytes));
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();

    let entries = archive
        .entries()
        .map_err(|e| WarmError::Storage(format!("TAR entry parse error: {e}")))?;

    for entry in entries {
        let mut entry =
            entry.map_err(|e| WarmError::Storage(format!("TAR entry read error: {e}")))?;
        let path = entry
            .path()
            .map_err(|e| WarmError::Storage(format!("TAR path read error: {e}")))?
            .to_string_lossy()
            .replace('\\', "/");
        let mut buf = Vec::new();
        entry
            .read_to_end(&mut buf)
            .map_err(|e| WarmError::Storage(format!("TAR entry data read error: {e}")))?;
        files.insert(path, buf);
    }

    let hashes_bytes = files.get("integrity/file-hashes.json").ok_or_else(|| {
        WarmError::Verification("Archive missing integrity/file-hashes.json".into())
    })?;
    let file_hashes: BTreeMap<String, String> = serde_json::from_slice(hashes_bytes)
        .map_err(|e| WarmError::Verification(format!("Invalid file-hashes.json: {e}")))?;

    for (path, expected_hash) in &file_hashes {
        let file_content = files.get(path).ok_or_else(|| {
            WarmError::Verification(format!("File declared in file-hashes.json missing: {path}"))
        })?;
        let computed = sha256_digest(file_content);
        if computed != *expected_hash {
            return Err(WarmError::Verification(format!(
                "Integrity violation: file '{path}' SHA-256 hash mismatch"
            )));
        }
    }

    let meta_path = format!("sessions/{}/metadata.json", session_id);
    let meta_bytes = files.get(&meta_path).ok_or_else(|| {
        WarmError::Verification(format!("Archive missing session metadata at {meta_path}"))
    })?;
    let metadata: WarmacSessionMetadata = serde_json::from_slice(meta_bytes)
        .map_err(|e| WarmError::Verification(format!("Invalid session metadata: {e}")))?;

    Ok(DecryptedWarmacArchive {
        contest_uuid,
        session_id,
        participant_id,
        files,
        file_hashes,
        metadata,
        raw_tar_bytes: tar_bytes,
    })
}

pub fn verify_warmac_file(
    file_path: &Path,
    judge_secret: &X25519StaticSecret,
) -> Result<DecryptedWarmacArchive> {
    let bytes = fs::read(file_path).map_err(|e| WarmError::Io(e.to_string()))?;
    unpack_warmac_package(&bytes, judge_secret)
}

pub fn inspect_warmac_container(warmac_bytes: &[u8]) -> Result<(Uuid, Uuid, String, usize)> {
    if warmac_bytes.len() < 86 {
        return Err(WarmError::Storage(
            "Warmac archive file is too small to be valid".into(),
        ));
    }
    if &warmac_bytes[0..8] != WARMAC_MAGIC {
        return Err(WarmError::Storage(
            "Invalid Warmac archive magic header".into(),
        ));
    }
    let contest_uuid = Uuid::from_slice(&warmac_bytes[8..24])
        .map_err(|e| WarmError::Storage(format!("Invalid contest UUID: {e}")))?;
    let session_id = Uuid::from_slice(&warmac_bytes[24..40])
        .map_err(|e| WarmError::Storage(format!("Invalid session UUID: {e}")))?;
    let pid_len = u16::from_le_bytes([warmac_bytes[40], warmac_bytes[41]]) as usize;
    let pid_end = 42 + pid_len;
    if warmac_bytes.len() < pid_end + 32 + 12 {
        return Err(WarmError::Storage(
            "Malformed Warmac archive header length".into(),
        ));
    }
    let participant_id = String::from_utf8(warmac_bytes[42..pid_end].to_vec())
        .map_err(|e| WarmError::Storage(format!("Invalid participant ID string: {e}")))?;
    let ciphertext_len = warmac_bytes.len() - (pid_end + 44);
    if ciphertext_len < 16 {
        return Err(WarmError::Storage(
            "Ciphertext too short for GCM tag".into(),
        ));
    }
    Ok((contest_uuid, session_id, participant_id, ciphertext_len))
}

pub fn inspect_warmac_file(file_path: &Path) -> Result<(Uuid, Uuid, String, usize)> {
    let bytes = fs::read(file_path).map_err(|e| WarmError::Io(e.to_string()))?;
    inspect_warmac_container(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqliteAuditStore;
    use warm_crypto::{seal_asymmetric_payload, EvidenceEncryptionKeypair};

    #[test]
    fn test_warmac_roundtrip_encryption_and_integrity_verification() {
        let store = SqliteAuditStore::open_in_memory().unwrap();
        let contest_uuid = Uuid::new_v4();
        let participant_id = "participant-warmac";
        let session_id = Uuid::new_v4();

        let judge_keypair = EvidenceEncryptionKeypair::generate();
        let mut tracker = crate::HashChainTracker::new(contest_uuid, participant_id);

        let now = Utc::now();
        let payload = serde_json::json!({"action": "Snapshot", "pid": 1234});
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let payload_hash = sha256_digest(&payload_bytes);
        let (seq, prev_h, curr_h) = tracker.step(
            &now.to_rfc3339(),
            warm_events::EventCategory::Process,
            &payload_hash,
        );
        let aad = format!("{}:{}:{}", contest_uuid, participant_id, seq).into_bytes();
        let sealed = seal_asymmetric_payload(
            &judge_keypair.public_key,
            &contest_uuid,
            &payload_bytes,
            &aad,
        )
        .unwrap();

        store
            .record_event(
                seq,
                Uuid::new_v4(),
                contest_uuid,
                participant_id,
                session_id,
                now,
                warm_events::EventCategory::Process,
                &sealed,
                &payload_hash,
                &prev_h,
                &curr_h,
            )
            .unwrap();

        let temp_dir = tempfile::tempdir().unwrap();
        let warmac_path = temp_dir.path().join("contest.warmac");

        let contest_manifest = serde_json::json!({"id": "gocup-1", "title": "GOCUP 1"});
        let manifest_bytes = serde_json::to_vec(&contest_manifest).unwrap();
        let sig_key = warm_crypto::ManifestSigningKeypair::generate();
        let sig_hex = sig_key.sign_hex(&manifest_bytes);

        let attachments = vec![("screenshot_001.bmp".to_string(), b"BM_MOCK_PIXELS".to_vec())];

        create_warmac_package(
            &warmac_path,
            &manifest_bytes,
            &sig_hex,
            &sig_key.public_key_hex(),
            &judge_keypair.public_key,
            &store,
            contest_uuid,
            participant_id,
            session_id,
            None,
            &attachments,
            None,
            None,
            &[],
        )
        .unwrap();

        assert!(warmac_path.exists());
        let warmac_bytes = fs::read(&warmac_path).unwrap();
        assert_eq!(&warmac_bytes[0..8], WARMAC_MAGIC);

        let decrypted = unpack_warmac_package(&warmac_bytes, &judge_keypair.secret_key).unwrap();
        assert_eq!(decrypted.contest_uuid, contest_uuid);
        assert_eq!(decrypted.session_id, session_id);
        assert_eq!(decrypted.participant_id, participant_id);

        assert!(decrypted.files.contains_key("manifest/contest.json"));
        assert!(decrypted.files.contains_key("manifest/signatures.json"));
        assert!(decrypted
            .files
            .contains_key(&format!("sessions/{session_id}/metadata.json")));
        assert!(decrypted
            .files
            .contains_key(&format!("sessions/{session_id}/events.jsonl")));
        assert!(decrypted.files.contains_key(&format!(
            "sessions/{session_id}/screenshots/screenshot_001.bmp"
        )));
        assert!(decrypted.files.contains_key("integrity/file-hashes.json"));
        assert!(decrypted.files.contains_key("integrity/audit-chain.json"));

        let wrong_keypair = EvidenceEncryptionKeypair::generate();
        assert!(unpack_warmac_package(&warmac_bytes, &wrong_keypair.secret_key).is_err());
    }
}
