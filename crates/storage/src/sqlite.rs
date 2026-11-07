use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use warm_core::{Result, WarmError};
use warm_crypto::{compute_event_hash, compute_genesis_hash, SealedPayload};
use warm_events::EventCategory;

/// Stored representation of an audit event as stored in SQLite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredAuditEvent {
    pub sequence_number: u64,
    pub event_uuid: Uuid,
    pub contest_uuid: Uuid,
    pub participant_id: String,
    pub session_id: Uuid,
    pub timestamp_rfc3339: String,
    pub category: String,
    pub sealed_payload: SealedPayload,
    pub payload_hash: String,
    pub previous_event_hash: String,
    pub current_event_hash: String,
}

/// Verification result details returned by `verify_integrity`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityReport {
    pub total_events: u64,
    pub is_valid: bool,
    pub first_sequence: Option<u64>,
    pub last_sequence: Option<u64>,
    pub genesis_hash: String,
    pub final_hash: Option<String>,
    pub anomalies: Vec<String>,
}

#[derive(Clone)]
pub struct SqliteAuditStore {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteAuditStore {
    /// Open or create an SQLite database on disk.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path)
            .map_err(|e| WarmError::Storage(format!("Failed to open SQLite database: {e}")))?;
        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        store.init_schema()?;
        Ok(store)
    }

    /// Open an ephemeral in-memory SQLite database (used for testing).
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()
            .map_err(|e| WarmError::Storage(format!("Failed to open in-memory SQLite: {e}")))?;
        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;

            CREATE TABLE IF NOT EXISTS audit_events (
                sequence_number INTEGER PRIMARY KEY,
                event_uuid TEXT NOT NULL UNIQUE,
                contest_uuid TEXT NOT NULL,
                participant_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                category TEXT NOT NULL,
                ephemeral_public_key TEXT NOT NULL,
                nonce TEXT NOT NULL,
                ciphertext TEXT NOT NULL,
                payload_hash TEXT NOT NULL,
                previous_event_hash TEXT NOT NULL,
                current_event_hash TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_audit_events_seq ON audit_events(sequence_number);
            CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events(timestamp);
            "#,
        )
        .map_err(|e| WarmError::Storage(format!("Failed to initialize database schema: {e}")))?;
        Ok(())
    }

    /// Record a sealed audit event into the append-only ledger.
    #[allow(clippy::too_many_arguments)]
    pub fn record_event(
        &self,
        sequence_number: u64,
        event_uuid: Uuid,
        contest_uuid: Uuid,
        participant_id: &str,
        session_id: Uuid,
        timestamp: DateTime<Utc>,
        category: EventCategory,
        sealed_payload: &SealedPayload,
        payload_hash: &str,
        previous_event_hash: &str,
        current_event_hash: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            r#"
            INSERT INTO audit_events (
                sequence_number,
                event_uuid,
                contest_uuid,
                participant_id,
                session_id,
                timestamp,
                category,
                ephemeral_public_key,
                nonce,
                ciphertext,
                payload_hash,
                previous_event_hash,
                current_event_hash
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
            "#,
            params![
                sequence_number as i64,
                event_uuid.to_string(),
                contest_uuid.to_string(),
                participant_id,
                session_id.to_string(),
                timestamp.to_rfc3339(),
                category.to_string(),
                sealed_payload.ephemeral_public_key_hex,
                sealed_payload.nonce_hex,
                sealed_payload.ciphertext_hex,
                payload_hash,
                previous_event_hash,
                current_event_hash,
            ],
        )
        .map_err(|e| WarmError::Storage(format!("Failed to insert audit event: {e}")))?;
        Ok(())
    }

    /// Force a WAL checkpoint to flush all committed transactions into the main database file.
    pub fn checkpoint(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .map_err(|e| WarmError::Storage(format!("WAL checkpoint failed: {e}")))?;
        Ok(())
    }

    /// Retrieve the highest recorded sequence number and its event hash for resuming state.
    pub fn get_latest_event_info(&self) -> Result<Option<(u64, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT sequence_number, current_event_hash FROM audit_events ORDER BY sequence_number DESC LIMIT 1",
            )
            .map_err(|e| WarmError::Storage(e.to_string()))?;

        let mut rows = stmt
            .query([])
            .map_err(|e| WarmError::Storage(e.to_string()))?;

        if let Some(row) = rows.next().map_err(|e| WarmError::Storage(e.to_string()))? {
            let seq: i64 = row.get(0).map_err(|e| WarmError::Storage(e.to_string()))?;
            let hash: String = row.get(1).map_err(|e| WarmError::Storage(e.to_string()))?;
            Ok(Some((seq as u64, hash)))
        } else {
            Ok(None)
        }
    }

    /// Retrieve total count of events in storage.
    pub fn get_event_count(&self) -> Result<u64> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM audit_events", [], |row| row.get(0))
            .map_err(|e| WarmError::Storage(e.to_string()))?;
        Ok(count as u64)
    }

    /// Retrieve all audit events in ascending sequence order.
    pub fn get_all_events(&self) -> Result<Vec<StoredAuditEvent>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                r#"
                SELECT
                    sequence_number,
                    event_uuid,
                    contest_uuid,
                    participant_id,
                    session_id,
                    timestamp,
                    category,
                    ephemeral_public_key,
                    nonce,
                    ciphertext,
                    payload_hash,
                    previous_event_hash,
                    current_event_hash
                FROM audit_events
                ORDER BY sequence_number ASC
                "#,
            )
            .map_err(|e| WarmError::Storage(e.to_string()))?;

        let rows = stmt
            .query_map([], |row| {
                let seq: i64 = row.get(0)?;
                let event_uuid_str: String = row.get(1)?;
                let contest_uuid_str: String = row.get(2)?;
                let participant_id: String = row.get(3)?;
                let session_id_str: String = row.get(4)?;
                let timestamp_rfc3339: String = row.get(5)?;
                let category: String = row.get(6)?;
                let ephemeral_public_key_hex: String = row.get(7)?;
                let nonce_hex: String = row.get(8)?;
                let ciphertext_hex: String = row.get(9)?;
                let payload_hash: String = row.get(10)?;
                let previous_event_hash: String = row.get(11)?;
                let current_event_hash: String = row.get(12)?;

                Ok(StoredAuditEvent {
                    sequence_number: seq as u64,
                    event_uuid: Uuid::parse_str(&event_uuid_str).unwrap_or_default(),
                    contest_uuid: Uuid::parse_str(&contest_uuid_str).unwrap_or_default(),
                    participant_id,
                    session_id: Uuid::parse_str(&session_id_str).unwrap_or_default(),
                    timestamp_rfc3339,
                    category,
                    sealed_payload: SealedPayload {
                        ephemeral_public_key_hex,
                        nonce_hex,
                        ciphertext_hex,
                    },
                    payload_hash,
                    previous_event_hash,
                    current_event_hash,
                })
            })
            .map_err(|e| WarmError::Storage(e.to_string()))?;

        let mut events = Vec::new();
        for r in rows {
            events.push(r.map_err(|e| WarmError::Storage(e.to_string()))?);
        }
        Ok(events)
    }

    /// Verifies the full cryptographic hash chain and sequence continuity from Genesis to End.
    pub fn verify_integrity(
        &self,
        expected_contest_uuid: &Uuid,
        expected_participant_id: &str,
    ) -> Result<IntegrityReport> {
        let events = self.get_all_events()?;
        let genesis_hash = compute_genesis_hash(expected_contest_uuid, expected_participant_id);

        if events.is_empty() {
            return Ok(IntegrityReport {
                total_events: 0,
                is_valid: true,
                first_sequence: None,
                last_sequence: None,
                genesis_hash,
                final_hash: None,
                anomalies: Vec::new(),
            });
        }

        let mut anomalies = Vec::new();
        let mut expected_seq = 1u64;
        let mut prev_hash = genesis_hash.clone();

        for (idx, event) in events.iter().enumerate() {
            // 1. Sequence number continuity
            if event.sequence_number != expected_seq {
                anomalies.push(format!(
                    "Sequence gap detected at index {}: expected {}, found {}",
                    idx, expected_seq, event.sequence_number
                ));
            }

            // 2. Contest UUID match
            if event.contest_uuid != *expected_contest_uuid {
                anomalies.push(format!(
                    "Contest UUID mismatch at seq {}: expected {}, found {}",
                    event.sequence_number, expected_contest_uuid, event.contest_uuid
                ));
            }

            // 3. Participant ID match
            if event.participant_id != expected_participant_id {
                anomalies.push(format!(
                    "Participant ID mismatch at seq {}: expected {}, found {}",
                    event.sequence_number, expected_participant_id, event.participant_id
                ));
            }

            // 4. Previous hash link check
            if event.previous_event_hash != prev_hash {
                anomalies.push(format!(
                    "Previous hash link mismatch at seq {}: expected {}, found {}",
                    event.sequence_number, prev_hash, event.previous_event_hash
                ));
            }

            // 5. Current hash re-computation check
            let computed_hash = compute_event_hash(
                event.sequence_number,
                &event.timestamp_rfc3339,
                &event.previous_event_hash,
                &event.category,
                &event.payload_hash,
            );

            if computed_hash != event.current_event_hash {
                anomalies.push(format!(
                    "Current hash mismatch at seq {}: computed {}, recorded {}",
                    event.sequence_number, computed_hash, event.current_event_hash
                ));
            }

            expected_seq = event.sequence_number + 1;
            prev_hash = event.current_event_hash.clone();
        }

        let first_seq = events.first().map(|e| e.sequence_number);
        let last_seq = events.last().map(|e| e.sequence_number);
        let final_hash = events.last().map(|e| e.current_event_hash.clone());
        let is_valid = anomalies.is_empty();

        Ok(IntegrityReport {
            total_events: events.len() as u64,
            is_valid,
            first_sequence: first_seq,
            last_sequence: last_seq,
            genesis_hash,
            final_hash,
            anomalies,
        })
    }
}
