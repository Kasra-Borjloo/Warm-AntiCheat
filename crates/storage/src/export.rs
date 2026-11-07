use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;
use warm_core::{Result, WarmError};
use warm_crypto::sha256_digest;

/// Metadata manifest accompanying exported evidence packages.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceExportManifest {
    pub contest_uuid: Uuid,
    pub participant_id: String,
    pub session_id: Uuid,
    pub total_events: u64,
    pub genesis_hash: String,
    pub final_hash: String,
    pub exported_at: DateTime<Utc>,
    pub database_sha256: String,
}

/// Package an SQLite database file and metadata manifest into a destination directory.
#[allow(clippy::too_many_arguments)]
pub fn export_evidence_package(
    db_source_path: &Path,
    destination_dir: &Path,
    contest_uuid: Uuid,
    participant_id: impl Into<String>,
    session_id: Uuid,
    total_events: u64,
    genesis_hash: impl Into<String>,
    final_hash: impl Into<String>,
) -> Result<PathBuf> {
    let participant_id = participant_id.into();
    if !db_source_path.exists() {
        return Err(WarmError::Storage(format!(
            "Source database does not exist: {}",
            db_source_path.display()
        )));
    }

    fs::create_dir_all(destination_dir)
        .map_err(|e| WarmError::Io(format!("Failed to create destination dir: {e}")))?;

    let db_bytes = fs::read(db_source_path)
        .map_err(|e| WarmError::Io(format!("Failed to read source database: {e}")))?;
    let db_sha256 = sha256_digest(&db_bytes);

    let target_db_path = destination_dir.join("evidence.sqlite");
    fs::write(&target_db_path, &db_bytes)
        .map_err(|e| WarmError::Io(format!("Failed to write evidence database: {e}")))?;

    let manifest = EvidenceExportManifest {
        contest_uuid,
        participant_id,
        session_id,
        total_events,
        genesis_hash: genesis_hash.into(),
        final_hash: final_hash.into(),
        exported_at: Utc::now(),
        database_sha256: db_sha256,
    };

    let manifest_json = serde_json::to_string_pretty(&manifest)
        .map_err(|e| WarmError::Serialization(e.to_string()))?;
    let manifest_path = destination_dir.join("manifest.json");
    fs::write(&manifest_path, manifest_json)
        .map_err(|e| WarmError::Io(format!("Failed to write export manifest: {e}")))?;

    Ok(destination_dir.to_path_buf())
}

/// Verify an exported evidence package's database integrity against its manifest.
pub fn verify_export_package(package_dir: &Path) -> Result<EvidenceExportManifest> {
    let manifest_path = package_dir.join("manifest.json");
    if !manifest_path.exists() {
        return Err(WarmError::Storage(format!(
            "Export package missing manifest.json at {}",
            manifest_path.display()
        )));
    }

    let manifest_str = fs::read_to_string(&manifest_path)
        .map_err(|e| WarmError::Io(format!("Failed to read manifest.json: {e}")))?;
    let manifest: EvidenceExportManifest = serde_json::from_str(&manifest_str)
        .map_err(|e| WarmError::Serialization(format!("Invalid manifest format: {e}")))?;

    let db_path = package_dir.join("evidence.sqlite");
    if !db_path.exists() {
        return Err(WarmError::Storage(format!(
            "Export package missing evidence.sqlite at {}",
            db_path.display()
        )));
    }

    let db_bytes = fs::read(&db_path)
        .map_err(|e| WarmError::Io(format!("Failed to read evidence.sqlite: {e}")))?;
    let computed_db_hash = sha256_digest(&db_bytes);

    if computed_db_hash != manifest.database_sha256 {
        return Err(WarmError::Verification(format!(
            "Database SHA256 mismatch! Expected {}, found {}",
            manifest.database_sha256, computed_db_hash
        )));
    }

    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_export_and_verify_package() {
        let temp_dir = std::env::temp_dir().join(format!("warm_export_test_{}", Uuid::new_v4()));
        fs::create_dir_all(&temp_dir).unwrap();

        let db_src = temp_dir.join("source.sqlite");
        fs::write(&db_src, b"SQLITE_DUMMY_DATABASE_CONTENT").unwrap();

        let export_dir = temp_dir.join("exported_package");
        let contest_uuid = Uuid::new_v4();
        let session_id = Uuid::new_v4();

        let res = export_evidence_package(
            &db_src,
            &export_dir,
            contest_uuid,
            "contestant-1",
            session_id,
            42,
            "genesis_hex",
            "final_hex",
        );
        assert!(res.is_ok());

        let verified = verify_export_package(&export_dir).expect("Verification should succeed");
        assert_eq!(verified.contest_uuid, contest_uuid);
        assert_eq!(verified.participant_id, "contestant-1");
        assert_eq!(verified.total_events, 42);

        // Tamper with database file
        fs::write(export_dir.join("evidence.sqlite"), b"TAMPERED_CONTENT").unwrap();
        assert!(verify_export_package(&export_dir).is_err());

        // Cleanup
        let _ = fs::remove_dir_all(temp_dir);
    }
}
