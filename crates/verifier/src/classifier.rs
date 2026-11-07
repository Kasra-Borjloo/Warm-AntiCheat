use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use warm_core::Result;
use warm_crypto::{open_asymmetric_payload, EvidenceEncryptionKeypair};
use warm_events::{BrowserEventPayload, ProcessEventPayload};
use warm_policies::MonitoringPolicy;
use warm_storage::SqliteAuditStore;

/// High-level competition integrity classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerdictClassification {
    /// No prohibited activity or tampering observed in the verified evidence.
    Safe,
    /// Verifiable, un-tampered evidence of prohibited activity was recorded.
    Unsafe,
    /// Incomplete, broken, interrupted, or anomalous evidence requiring human jury investigation.
    ReviewRequired,
}

impl std::fmt::Display for VerdictClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Safe => write!(f, "SAFE"),
            Self::Unsafe => write!(f, "UNSAFE"),
            Self::ReviewRequired => write!(f, "REVIEW REQUIRED"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingSeverity {
    Critical,
    Warning,
    Info,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForensicFinding {
    pub severity: FindingSeverity,
    pub title: String,
    pub description: String,
    pub supporting_sequences: Vec<u64>,
    pub timestamps: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecryptedTimelineEvent {
    pub sequence_number: u64,
    pub timestamp_rfc3339: String,
    pub category: String,
    pub payload_json: serde_json::Value,
    pub current_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForensicReport {
    pub contest_uuid: Uuid,
    pub participant_id: String,
    pub session_id: Uuid,
    pub classification: VerdictClassification,
    pub summary: String,
    pub total_events: u64,
    pub hash_chain_verified: bool,
    pub findings: Vec<ForensicFinding>,
    pub timeline: Vec<DecryptedTimelineEvent>,
    pub judge_notes: Option<String>,
}

pub struct ForensicVerifier {
    policy: MonitoringPolicy,
    judge_keypair: EvidenceEncryptionKeypair,
}

impl ForensicVerifier {
    pub fn new(policy: MonitoringPolicy, judge_keypair: EvidenceEncryptionKeypair) -> Self {
        Self {
            policy,
            judge_keypair,
        }
    }

    /// Execute complete forensic audit on a stored participant audit database.
    pub fn audit_store(
        &self,
        store: &SqliteAuditStore,
        expected_contest_uuid: &Uuid,
        expected_participant_id: &str,
    ) -> Result<ForensicReport> {
        // 1. Verify cryptographic hash chain integrity
        let integrity = store.verify_integrity(expected_contest_uuid, expected_participant_id)?;

        let mut findings = Vec::new();
        let mut classification = VerdictClassification::Safe;

        if !integrity.is_valid {
            classification = VerdictClassification::ReviewRequired;
            for anomaly in &integrity.anomalies {
                findings.push(ForensicFinding {
                    severity: FindingSeverity::Critical,
                    title: "Hash Chain Anomaly".to_string(),
                    description: anomaly.clone(),
                    supporting_sequences: vec![],
                    timestamps: vec![],
                });
            }
        }

        // 2. Fetch all stored events
        let raw_events = store.get_all_events()?;
        let mut timeline = Vec::new();
        let session_id = raw_events
            .first()
            .map(|e| e.session_id)
            .unwrap_or_else(Uuid::new_v4);

        let mut last_heartbeat_time: Option<DateTime<Utc>> = None;

        // 3. Decrypt and evaluate each event against policies
        for event in &raw_events {
            let aad = format!(
                "{}:{}:{}",
                event.contest_uuid, event.participant_id, event.sequence_number
            )
            .into_bytes();

            let decrypted_bytes = open_asymmetric_payload(
                &self.judge_keypair.secret_key,
                &event.contest_uuid,
                &event.sealed_payload,
                &aad,
            );

            let payload_value = match decrypted_bytes {
                Ok(bytes) => {
                    serde_json::from_slice::<serde_json::Value>(&bytes).unwrap_or_default()
                }
                Err(e) => {
                    classification = VerdictClassification::ReviewRequired;
                    findings.push(ForensicFinding {
                        severity: FindingSeverity::Critical,
                        title: "Decryption / Authentication Failure".to_string(),
                        description: format!(
                            "Failed to authenticate payload at sequence {}: {e}",
                            event.sequence_number
                        ),
                        supporting_sequences: vec![event.sequence_number],
                        timestamps: vec![event.timestamp_rfc3339.clone()],
                    });
                    serde_json::json!({"error": "DECRYPTION_FAILED"})
                }
            };

            // Policy Rule Evaluations:
            // A. Check for Prohibited Application
            if event.category == "Process" {
                if let Ok(proc_payload) =
                    serde_json::from_value::<ProcessEventPayload>(payload_value.clone())
                {
                    if self.policy.app_policy.is_prohibited(&proc_payload.name) {
                        classification = VerdictClassification::Unsafe;
                        findings.push(ForensicFinding {
                            severity: FindingSeverity::Critical,
                            title: "Prohibited Application Executed".to_string(),
                            description: format!(
                                "Prohibited application '{}' (PID: {}) executed during active contest.",
                                proc_payload.name, proc_payload.pid
                            ),
                            supporting_sequences: vec![event.sequence_number],
                            timestamps: vec![event.timestamp_rfc3339.clone()],
                        });
                    }
                }
            }

            // B. Check for Restricted Domain Access
            if event.category == "Browser" {
                if let Ok(browser_payload) =
                    serde_json::from_value::<BrowserEventPayload>(payload_value.clone())
                {
                    if self
                        .policy
                        .browser_policy
                        .is_restricted(&browser_payload.domain)
                    {
                        classification = VerdictClassification::Unsafe;
                        findings.push(ForensicFinding {
                            severity: FindingSeverity::Critical,
                            title: "Restricted Domain Navigated".to_string(),
                            description: format!(
                                "Restricted domain '{}' accessed during contest.",
                                browser_payload.domain
                            ),
                            supporting_sequences: vec![event.sequence_number],
                            timestamps: vec![event.timestamp_rfc3339.clone()],
                        });
                    }
                }
            }

            // C. Check for Compiler Activity & Resource Violations
            if event.category == "Compiler" {
                if let Ok(compiler_payload) = serde_json::from_value::<
                    warm_events::CompilerEventPayload,
                >(payload_value.clone())
                {
                    if let Some(ref violation) = compiler_payload.resource_violations {
                        findings.push(ForensicFinding {
                            severity: FindingSeverity::Warning,
                            title: "Compiler Resource Limit Exceeded".to_string(),
                            description: format!(
                                "Compiled executable triggered resource limit: {violation} (Source: {})",
                                compiler_payload.source_path
                            ),
                            supporting_sequences: vec![event.sequence_number],
                            timestamps: vec![event.timestamp_rfc3339.clone()],
                        });
                    }
                }
            }

            // D. Check for Monitoring Gaps & Sleep Interruptions
            if let Ok(dt) = DateTime::parse_from_rfc3339(&event.timestamp_rfc3339) {
                let dt_utc = dt.with_timezone(&Utc);
                if let Some(prev_time) = last_heartbeat_time {
                    let gap = (dt_utc - prev_time).num_seconds();
                    if gap > self.policy.max_interruption_gap_secs as i64 {
                        if classification != VerdictClassification::Unsafe {
                            classification = VerdictClassification::ReviewRequired;
                        }
                        findings.push(ForensicFinding {
                            severity: FindingSeverity::Warning,
                            title: "Monitoring Interruption / Sleep Gap".to_string(),
                            description: format!(
                                "Unexplained time gap of {gap}s between sequence {} and {}",
                                event.sequence_number - 1,
                                event.sequence_number
                            ),
                            supporting_sequences: vec![
                                event.sequence_number - 1,
                                event.sequence_number,
                            ],
                            timestamps: vec![event.timestamp_rfc3339.clone()],
                        });
                    }
                }
                last_heartbeat_time = Some(dt_utc);
            }

            timeline.push(DecryptedTimelineEvent {
                sequence_number: event.sequence_number,
                timestamp_rfc3339: event.timestamp_rfc3339.clone(),
                category: event.category.clone(),
                payload_json: payload_value,
                current_hash: event.current_event_hash.clone(),
            });
        }

        let summary = match classification {
            VerdictClassification::Safe => {
                format!(
                    "SAFE: Analyzed {} events across complete hash chain. No prohibited applications, restricted domains, or integrity anomalies were observed.",
                    raw_events.len()
                )
            }
            VerdictClassification::Unsafe => {
                format!(
                    "UNSAFE: Detected {} critical policy violations. Verifiable evidence of prohibited activity exists in audit log.",
                    findings.iter().filter(|f| f.severity == FindingSeverity::Critical).count()
                )
            }
            VerdictClassification::ReviewRequired => {
                format!(
                    "REVIEW REQUIRED: Audit log contains {} findings, anomalies, or monitoring interruptions requiring jury inquiry.",
                    findings.len()
                )
            }
        };

        Ok(ForensicReport {
            contest_uuid: *expected_contest_uuid,
            participant_id: expected_participant_id.to_string(),
            session_id,
            classification,
            summary,
            total_events: raw_events.len() as u64,
            hash_chain_verified: integrity.is_valid,
            findings,
            timeline,
            judge_notes: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use warm_crypto::{seal_asymmetric_payload, sha256_digest};
    use warm_events::{EventCategory, ProcessAction};

    #[test]
    fn test_forensic_verifier_safe_verdict() {
        let store = SqliteAuditStore::open_in_memory().unwrap();
        let contest_uuid = Uuid::new_v4();
        let participant_id = "user-clean";
        let judge_keypair = EvidenceEncryptionKeypair::generate();
        let policy = MonitoringPolicy::default();

        let verifier = ForensicVerifier::new(policy, judge_keypair);
        let report = verifier
            .audit_store(&store, &contest_uuid, participant_id)
            .unwrap();

        assert_eq!(report.classification, VerdictClassification::Safe);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn test_forensic_verifier_unsafe_verdict() {
        let store = SqliteAuditStore::open_in_memory().unwrap();
        let contest_uuid = Uuid::new_v4();
        let participant_id = "user-cheater";
        let judge_keypair = EvidenceEncryptionKeypair::generate();
        let policy = MonitoringPolicy::default();

        let mut tracker = warm_storage::HashChainTracker::new(contest_uuid, participant_id);

        // Record a prohibited Ollama execution event
        let proc_payload = ProcessEventPayload {
            pid: 1234,
            name: "ollama.exe".to_string(),
            path: Some("C:\\bin\\ollama.exe".to_string()),
            cmdline: Some("ollama run llama3".to_string()),
            action: ProcessAction::Started,
        };
        let payload_json = serde_json::to_vec(&proc_payload).unwrap();
        let payload_hash = sha256_digest(&payload_json);
        let now = Utc::now();

        let (seq, prev_hash, curr_hash) =
            tracker.step(&now.to_rfc3339(), EventCategory::Process, &payload_hash);
        let aad = format!("{}:{}:{}", contest_uuid, participant_id, seq).into_bytes();
        let sealed = seal_asymmetric_payload(
            &judge_keypair.public_key,
            &contest_uuid,
            &payload_json,
            &aad,
        )
        .unwrap();

        store
            .record_event(
                seq,
                Uuid::new_v4(),
                contest_uuid,
                participant_id,
                Uuid::new_v4(),
                now,
                EventCategory::Process,
                &sealed,
                &payload_hash,
                &prev_hash,
                &curr_hash,
            )
            .unwrap();

        let verifier = ForensicVerifier::new(policy, judge_keypair);
        let report = verifier
            .audit_store(&store, &contest_uuid, participant_id)
            .unwrap();

        assert_eq!(report.classification, VerdictClassification::Unsafe);
        assert_eq!(report.findings.len(), 1);
        assert!(report.findings[0]
            .title
            .contains("Prohibited Application Executed"));
    }
}
