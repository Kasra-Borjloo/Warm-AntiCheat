use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;
use uuid::Uuid;
use warm_core::Result;
use warm_crypto::{open_asymmetric_payload, EvidenceEncryptionKeypair};
use warm_events::{BrowserEventPayload, ProcessEventPayload};
use warm_policies::MonitoringPolicy;
use warm_storage::SqliteAuditStore;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerdictClassification {
    Safe,
    Unsafe,
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
pub struct ScreenshotEvidence {
    pub attachment_id: Uuid,
    pub filename: String,
    pub mime_type: String,
    pub triggering_sequence: u64,
    pub timestamp_rfc3339: String,
    pub reason: String,
    pub data_base64: String,
    #[serde(default)]
    pub contest_relative_time: Option<String>,
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
    #[serde(default)]
    pub authenticated_account_id: Option<Uuid>,
    #[serde(default)]
    pub declared_log_name: Option<String>,
    #[serde(default)]
    pub participation_mode: warm_core::ParticipationMode,
    #[serde(default)]
    pub screenshots: Vec<ScreenshotEvidence>,
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

    pub fn audit_store(
        &self,
        store: &SqliteAuditStore,
        expected_contest_uuid: &Uuid,
        expected_participant_id: &str,
    ) -> Result<ForensicReport> {
        let integrity = store.verify_integrity(expected_contest_uuid, expected_participant_id)?;
        let raw_events = store.get_all_events()?;
        let session_id = raw_events
            .first()
            .map(|e| e.session_id)
            .unwrap_or_else(Uuid::new_v4);

        self.evaluate_events(
            expected_contest_uuid,
            expected_participant_id,
            session_id,
            &raw_events,
            integrity.is_valid,
            &integrity.anomalies,
            None,
        )
    }

    pub fn audit_warmac_archive(&self, warmac_path: &Path) -> Result<ForensicReport> {
        let archive =
            warm_storage::verify_warmac_file(warmac_path, &self.judge_keypair.secret_key)?;

        let events_path = format!("sessions/{}/events.jsonl", archive.session_id);
        let events_bytes = archive.files.get(&events_path).ok_or_else(|| {
            warm_core::WarmError::Verification(format!("Missing {events_path} in archive"))
        })?;

        let events_str = String::from_utf8(events_bytes.clone())
            .map_err(|e| warm_core::WarmError::Verification(e.to_string()))?;

        let mut raw_events = Vec::new();
        for line in events_str.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let v: serde_json::Value = serde_json::from_str(line)
                .map_err(|e| warm_core::WarmError::Verification(e.to_string()))?;

            let seq = v["sequence_number"].as_u64().unwrap_or(0);
            let event_uuid =
                Uuid::parse_str(v["event_uuid"].as_str().unwrap_or("")).unwrap_or_default();
            let contest_uuid =
                Uuid::parse_str(v["contest_uuid"].as_str().unwrap_or("")).unwrap_or_default();
            let participant_id = v["participant_id"].as_str().unwrap_or("").to_string();
            let session_id =
                Uuid::parse_str(v["session_id"].as_str().unwrap_or("")).unwrap_or_default();
            let timestamp_rfc3339 = v["timestamp"].as_str().unwrap_or("").to_string();
            let category = v["category"].as_str().unwrap_or("").to_string();
            let payload_hash = v["payload_hash"].as_str().unwrap_or("").to_string();
            let previous_event_hash = v["previous_event_hash"].as_str().unwrap_or("").to_string();
            let current_event_hash = v["current_event_hash"].as_str().unwrap_or("").to_string();

            let sealed_val = &v["sealed_payload"];
            let ephemeral_public_key_hex = sealed_val["ephemeral_public_key_hex"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let nonce_hex = sealed_val["nonce_hex"].as_str().unwrap_or("").to_string();
            let ciphertext_hex = sealed_val["ciphertext_hex"]
                .as_str()
                .unwrap_or("")
                .to_string();

            raw_events.push(warm_storage::StoredAuditEvent {
                sequence_number: seq,
                event_uuid,
                contest_uuid,
                participant_id,
                session_id,
                timestamp_rfc3339,
                category,
                sealed_payload: warm_crypto::SealedPayload {
                    ephemeral_public_key_hex,
                    nonce_hex,
                    ciphertext_hex,
                },
                payload_hash,
                previous_event_hash,
                current_event_hash,
            });
        }

        let genesis_hash =
            warm_crypto::compute_genesis_hash(&archive.contest_uuid, &archive.participant_id);
        let mut prev_h = genesis_hash;
        let mut anomalies = Vec::new();

        for (expected_seq, (idx, ev)) in (1u64..).zip(raw_events.iter().enumerate()) {
            if ev.sequence_number != expected_seq {
                anomalies.push(format!(
                    "Sequence gap at index {idx}: expected {expected_seq}, found {}",
                    ev.sequence_number
                ));
            }
            if ev.previous_event_hash != prev_h {
                anomalies.push(format!(
                    "Previous hash mismatch at sequence {}: expected {prev_h}, found {}",
                    ev.sequence_number, ev.previous_event_hash
                ));
            }
            let computed = warm_crypto::compute_event_hash(
                ev.sequence_number,
                &ev.timestamp_rfc3339,
                &ev.previous_event_hash,
                &ev.category,
                &ev.payload_hash,
            );
            if computed != ev.current_event_hash {
                anomalies.push(format!(
                    "Current hash verification failed at sequence {}",
                    ev.sequence_number
                ));
            }
            prev_h = ev.current_event_hash.clone();
        }

        let mut report = self.evaluate_events(
            &archive.contest_uuid,
            &archive.participant_id,
            archive.session_id,
            &raw_events,
            anomalies.is_empty(),
            &anomalies,
            archive.metadata.authenticated_account_id,
        )?;

        if archive.metadata.file_tamper_count > 0 {
            report.findings.push(ForensicFinding {
                severity: FindingSeverity::Critical,
                title: "Unauthorized Evidence File Tampering / Deletion Detected".to_string(),
                description: format!(
                    "Participant attempted to delete or modify the .warmac container {} times. Attempt records: {:?}",
                    archive.metadata.file_tamper_count, archive.metadata.file_tamper_attempts
                ),
                supporting_sequences: vec![],
                timestamps: archive.metadata.file_tamper_attempts.clone(),
            });
            report.classification = VerdictClassification::Unsafe;
        }

        for (rel_path, content) in &archive.files {
            if rel_path.starts_with(&format!("sessions/{}/screenshots/", archive.session_id)) {
                let filename = rel_path
                    .split('/')
                    .next_back()
                    .unwrap_or("screenshot.bmp")
                    .to_string();
                let b64 = base64::engine::general_purpose::STANDARD.encode(content);

                let mut rel_time = None;
                let mut reason_str =
                    "Event-triggered screenshot evidence captured during suspicious activity"
                        .to_string();
                let mut seq_num = 0;
                let mut ts_str = archive.metadata.exported_at.to_rfc3339();

                for ev in &report.timeline {
                    if let Ok(proc_ev) = serde_json::from_value::<warm_events::ProcessEventPayload>(
                        ev.payload_json.clone(),
                    ) {
                        if let Some(att) = proc_ev.screenshot_attachment {
                            if att.filename == filename {
                                rel_time = att.contest_relative_time;
                                reason_str = att.reason;
                                seq_num = ev.sequence_number;
                                ts_str = att.captured_at.to_rfc3339();
                                break;
                            }
                        }
                    }
                    if let Ok(b_ev) = serde_json::from_value::<warm_events::BrowserEventPayload>(
                        ev.payload_json.clone(),
                    ) {
                        if let Some(att) = b_ev.screenshot_attachment {
                            if att.filename == filename {
                                rel_time = att.contest_relative_time;
                                reason_str = att.reason;
                                seq_num = ev.sequence_number;
                                ts_str = att.captured_at.to_rfc3339();
                                break;
                            }
                        }
                    }
                }

                report.screenshots.push(ScreenshotEvidence {
                    attachment_id: Uuid::new_v4(),
                    filename,
                    mime_type: "image/bmp".to_string(),
                    triggering_sequence: seq_num,
                    timestamp_rfc3339: ts_str,
                    reason: reason_str,
                    data_base64: b64,
                    contest_relative_time: rel_time,
                });
            }
        }

        Ok(report)
    }

    #[allow(clippy::too_many_arguments)]
    fn evaluate_events(
        &self,
        contest_uuid: &Uuid,
        participant_id: &str,
        session_id: Uuid,
        raw_events: &[warm_storage::StoredAuditEvent],
        is_integrity_valid: bool,
        integrity_anomalies: &[String],
        account_id_override: Option<Uuid>,
    ) -> Result<ForensicReport> {
        let mut findings = Vec::new();
        let mut classification = VerdictClassification::Safe;

        if !is_integrity_valid {
            classification = VerdictClassification::ReviewRequired;
            for anomaly in integrity_anomalies {
                findings.push(ForensicFinding {
                    severity: FindingSeverity::Critical,
                    title: "Hash Chain Anomaly".to_string(),
                    description: anomaly.clone(),
                    supporting_sequences: vec![],
                    timestamps: vec![],
                });
            }
        }

        let mut timeline = Vec::new();
        let mut last_heartbeat_time: Option<DateTime<Utc>> = None;
        let mut authenticated_account_id: Option<Uuid> = None;
        let mut failed_auth_count = 0;

        for event in raw_events {
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

                    if !proc_payload.listening_ports.is_empty() {
                        classification = VerdictClassification::Unsafe;
                        findings.push(ForensicFinding {
                            severity: FindingSeverity::Critical,
                            title: "Local AI Inference Service Detected".to_string(),
                            description: format!(
                                "Active local AI service '{}' detected listening on port(s): {:?}",
                                proc_payload.name, proc_payload.listening_ports
                            ),
                            supporting_sequences: vec![event.sequence_number],
                            timestamps: vec![event.timestamp_rfc3339.clone()],
                        });
                    }

                    if let Some(ref cmdline) = proc_payload.cmdline {
                        if let Some((rule_name, detail)) =
                            warm_policies::AppPolicy::inspect_command_line(cmdline)
                        {
                            classification = VerdictClassification::Unsafe;
                            findings.push(ForensicFinding {
                                severity: FindingSeverity::Critical,
                                title: format!("Local AI Inference Runtime Detected ({rule_name})"),
                                description: format!(
                                    "Process '{}' (PID: {}) executed local AI inference: {detail}. Command line: {cmdline}",
                                    proc_payload.name, proc_payload.pid
                                ),
                                supporting_sequences: vec![event.sequence_number],
                                timestamps: vec![event.timestamp_rfc3339.clone()],
                            });
                        }
                    }
                }
            }

            if event.category == "Browser" {
                if let Ok(browser_payload) =
                    serde_json::from_value::<BrowserEventPayload>(payload_value.clone())
                {
                    if browser_payload.is_restricted
                        || self
                            .policy
                            .browser_policy
                            .is_restricted(&browser_payload.domain)
                    {
                        classification = VerdictClassification::Unsafe;
                        findings.push(ForensicFinding {
                            severity: FindingSeverity::Critical,
                            title: "Restricted Domain or AI Assistant Accessed".to_string(),
                            description: format!(
                                "Restricted domain / AI assistant '{}' accessed during contest. Window: {}",
                                browser_payload.domain,
                                browser_payload.window_title.as_deref().unwrap_or("Active Browser Window")
                            ),
                            supporting_sequences: vec![event.sequence_number],
                            timestamps: vec![event.timestamp_rfc3339.clone()],
                        });
                    }
                }
            }

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

            if event.category == "Auth" {
                if let Ok(auth_payload) =
                    serde_json::from_value::<warm_events::AuthEventPayload>(payload_value.clone())
                {
                    match auth_payload.action {
                        warm_events::AuthAction::LoginSuccess => {
                            authenticated_account_id = auth_payload.account_id;
                        }
                        warm_events::AuthAction::LoginFailure => {
                            failed_auth_count += 1;
                        }
                        warm_events::AuthAction::Logout => {}
                    }
                }
            }

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

        if failed_auth_count > 5 {
            findings.push(ForensicFinding {
                severity: FindingSeverity::Warning,
                title: "Excessive Authentication Failures".to_string(),
                description: format!(
                    "{failed_auth_count} failed authentication attempts recorded."
                ),
                supporting_sequences: vec![],
                timestamps: vec![],
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

        let final_account_id = account_id_override.or(authenticated_account_id);
        Ok(ForensicReport {
            contest_uuid: *contest_uuid,
            participant_id: participant_id.to_string(),
            session_id,
            classification,
            summary,
            total_events: raw_events.len() as u64,
            hash_chain_verified: is_integrity_valid,
            findings,
            timeline,
            judge_notes: None,
            authenticated_account_id: final_account_id,
            declared_log_name: if final_account_id.is_none() {
                Some(participant_id.to_string())
            } else {
                None
            },
            participation_mode: if final_account_id.is_some() {
                warm_core::ParticipationMode::GeneratedAccounts
            } else {
                warm_core::ParticipationMode::NoAccounts
            },
            screenshots: Vec::new(),
        })
    }
}

pub fn detect_duplicate_account_sessions(reports: &[ForensicReport]) -> Vec<ForensicFinding> {
    use std::collections::HashMap;
    let mut map: HashMap<Uuid, Vec<(&str, Uuid)>> = HashMap::new();
    for r in reports {
        if let Some(acc_id) = r.authenticated_account_id {
            map.entry(acc_id)
                .or_default()
                .push((&r.participant_id, r.session_id));
        }
    }

    let mut findings = Vec::new();
    for (acc_id, sessions) in map {
        if sessions.len() > 1 {
            let session_list = sessions
                .iter()
                .map(|(p, s)| format!("{p} (session {s})"))
                .collect::<Vec<_>>()
                .join(", ");
            findings.push(ForensicFinding {
                severity: FindingSeverity::Critical,
                title: "Duplicate Account ID Detected".to_string(),
                description: format!(
                    "Account ID {acc_id} was observed across {} distinct sessions: {session_list}. Multiple sessions detected under same credential.",
                    sessions.len()
                ),
                supporting_sequences: vec![],
                timestamps: vec![],
            });
        }
    }
    findings
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

        let proc_payload = ProcessEventPayload {
            pid: 1234,
            name: "ollama.exe".to_string(),
            path: Some("C:\\bin\\ollama.exe".to_string()),
            cmdline: Some("ollama run llama3".to_string()),
            action: ProcessAction::Started,
            screenshot_attachment: None,
            listening_ports: vec![],
            cpu_usage: None,
            memory_bytes: None,
            is_anomalous_resource: false,
            contest_relative_time: None,
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

    #[test]
    fn test_detect_duplicate_account_sessions() {
        let account_id = Uuid::new_v4();
        let report1 = ForensicReport {
            contest_uuid: Uuid::new_v4(),
            participant_id: "participant-1".to_string(),
            session_id: Uuid::new_v4(),
            classification: VerdictClassification::Safe,
            summary: String::new(),
            total_events: 10,
            hash_chain_verified: true,
            findings: vec![],
            timeline: vec![],
            judge_notes: None,
            authenticated_account_id: Some(account_id),
            declared_log_name: None,
            participation_mode: warm_core::ParticipationMode::GeneratedAccounts,
            screenshots: Vec::new(),
        };

        let report2 = ForensicReport {
            contest_uuid: Uuid::new_v4(),
            participant_id: "participant-2".to_string(),
            session_id: Uuid::new_v4(),
            classification: VerdictClassification::Safe,
            summary: String::new(),
            total_events: 12,
            hash_chain_verified: true,
            findings: vec![],
            timeline: vec![],
            judge_notes: None,
            authenticated_account_id: Some(account_id),
            declared_log_name: None,
            participation_mode: warm_core::ParticipationMode::GeneratedAccounts,
            screenshots: Vec::new(),
        };

        let duplicate_findings = detect_duplicate_account_sessions(&[report1, report2]);
        assert_eq!(duplicate_findings.len(), 1);
        assert_eq!(duplicate_findings[0].severity, FindingSeverity::Critical);
        assert!(duplicate_findings[0]
            .title
            .contains("Duplicate Account ID Detected"));
    }

    #[test]
    fn test_python_ai_inference_detection_vs_clean_script() {
        use warm_crypto::{seal_asymmetric_payload, sha256_digest};
        use warm_events::{EventCategory, ProcessAction};

        let store = SqliteAuditStore::open_in_memory().unwrap();

        let contest_uuid = Uuid::new_v4();
        let participant_id = "participant-ai-test";
        let session_id = Uuid::new_v4();
        let mut tracker = warm_storage::HashChainTracker::new(contest_uuid, participant_id);

        let judge_keypair = EvidenceEncryptionKeypair::generate();
        let policy = MonitoringPolicy::default();

        let clean_proc = ProcessEventPayload {
            pid: 2001,
            name: "python.exe".to_string(),
            path: Some("C:\\Python311\\python.exe".to_string()),
            cmdline: Some("python solution.py".to_string()),
            action: ProcessAction::Started,
            screenshot_attachment: None,
            listening_ports: Vec::new(),
            cpu_usage: None,
            memory_bytes: None,
            is_anomalous_resource: false,
            contest_relative_time: None,
        };
        let clean_json = serde_json::to_vec(&clean_proc).unwrap();
        let clean_hash = sha256_digest(&clean_json);
        let now = Utc::now();
        let (seq1, prev_hash1, curr_hash1) =
            tracker.step(&now.to_rfc3339(), EventCategory::Process, &clean_hash);
        let aad1 = format!("{}:{}:{}", contest_uuid, participant_id, seq1).into_bytes();
        let sealed1 =
            seal_asymmetric_payload(&judge_keypair.public_key, &contest_uuid, &clean_json, &aad1)
                .unwrap();
        store
            .record_event(
                seq1,
                Uuid::new_v4(),
                contest_uuid,
                participant_id,
                session_id,
                now,
                EventCategory::Process,
                &sealed1,
                &clean_hash,
                &prev_hash1,
                &curr_hash1,
            )
            .unwrap();

        let verifier = ForensicVerifier::new(policy.clone(), judge_keypair.clone());
        let report_clean = verifier
            .audit_store(&store, &contest_uuid, participant_id)
            .unwrap();
        assert_eq!(report_clean.classification, VerdictClassification::Safe);
        assert!(report_clean.findings.is_empty());

        let ai_proc = ProcessEventPayload {
            pid: 2002,
            name: "python.exe".to_string(),
            path: Some("C:\\Python311\\python.exe".to_string()),
            cmdline: Some("python -m llama_cpp.server --model mistral.gguf".to_string()),
            action: ProcessAction::Started,
            screenshot_attachment: None,
            listening_ports: vec![],
            cpu_usage: None,
            memory_bytes: None,
            is_anomalous_resource: false,
            contest_relative_time: None,
        };
        let ai_json = serde_json::to_vec(&ai_proc).unwrap();
        let ai_hash = sha256_digest(&ai_json);
        let (seq2, prev_hash2, curr_hash2) =
            tracker.step(&now.to_rfc3339(), EventCategory::Process, &ai_hash);
        let aad2 = format!("{}:{}:{}", contest_uuid, participant_id, seq2).into_bytes();
        let sealed2 =
            seal_asymmetric_payload(&judge_keypair.public_key, &contest_uuid, &ai_json, &aad2)
                .unwrap();
        store
            .record_event(
                seq2,
                Uuid::new_v4(),
                contest_uuid,
                participant_id,
                session_id,
                now,
                EventCategory::Process,
                &sealed2,
                &ai_hash,
                &prev_hash2,
                &curr_hash2,
            )
            .unwrap();

        let report_ai = verifier
            .audit_store(&store, &contest_uuid, participant_id)
            .unwrap();
        assert_eq!(report_ai.classification, VerdictClassification::Unsafe);
        assert_eq!(report_ai.findings.len(), 1);
        assert!(report_ai.findings[0].title.contains("Local AI Inference"));
    }
}
