#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;
use warm_audit::{DeterministicAuditEngine, LocalAiSummarizer};
use warm_crypto::{verify_signature_hex, EvidenceEncryptionKeypair};
use warm_policies::MonitoringPolicy;
use warm_storage::SqliteAuditStore;
use warm_verifier::ForensicVerifier;

#[derive(Debug, Serialize, Deserialize)]
pub struct ManifestVerificationResult {
    pub valid: bool,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditReportResponse {
    pub verdict: String,
    pub participant_id: String,
    pub total_events: usize,
    pub violations: Vec<String>,
    pub summary_text: String,
    pub ai_advisory: String,
    pub authenticated_account_id: Option<String>,
    pub declared_log_name: Option<String>,
    pub participation_mode: String,
    #[serde(default)]
    pub screenshots: Vec<warm_verifier::ScreenshotEvidence>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DuplicateAccountCheckResult {
    pub has_duplicates: bool,
    pub findings: Vec<String>,
}

#[tauri::command]
fn check_duplicate_accounts(account_ids: Vec<String>) -> DuplicateAccountCheckResult {
    use std::collections::HashMap;
    let mut counts: HashMap<String, usize> = HashMap::new();
    for id in account_ids {
        if !id.is_empty() {
            *counts.entry(id).or_insert(0) += 1;
        }
    }
    let mut findings = Vec::new();
    for (id, count) in counts {
        if count > 1 {
            findings.push(format!(
                "Account ID '{id}' was submitted across {count} separate participant archives."
            ));
        }
    }
    DuplicateAccountCheckResult {
        has_duplicates: !findings.is_empty(),
        findings,
    }
}

#[tauri::command]
fn get_judge_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[tauri::command]
fn verify_manifest_file(
    manifest_path: String,
    sig_path: String,
    pk_path: String,
) -> Result<ManifestVerificationResult, String> {
    let m_path = PathBuf::from(manifest_path);
    let s_path = PathBuf::from(sig_path);
    let p_path = PathBuf::from(pk_path);

    if !m_path.exists() || !s_path.exists() || !p_path.exists() {
        return Err("One or more manifest/signature/key files not found on disk.".to_string());
    }

    let manifest_bytes = fs::read(&m_path).map_err(|e| e.to_string())?;
    let sig_hex = fs::read_to_string(&s_path).map_err(|e| e.to_string())?;
    let pk_hex = fs::read_to_string(&p_path).map_err(|e| e.to_string())?;

    match verify_signature_hex(&pk_hex, &manifest_bytes, &sig_hex) {
        Ok(()) => Ok(ManifestVerificationResult {
            valid: true,
            message: "Ed25519 digital signature is VALID and authentic.".to_string(),
        }),
        Err(e) => Ok(ManifestVerificationResult {
            valid: false,
            message: format!("Signature verification failed: {e}"),
        }),
    }
}

fn locate_judge_key(key_path: Option<String>, db_path: &Path) -> Option<EvidenceEncryptionKeypair> {
    let mut candidates = Vec::new();
    if let Some(kp) = key_path {
        candidates.push(PathBuf::from(kp));
    }
    if let Some(parent) = db_path.parent() {
        candidates.push(parent.join("judge_evidence_key.priv"));
        candidates.push(parent.join("keys").join("judge_evidence_key.priv"));
        if let Some(gp) = parent.parent() {
            candidates.push(
                gp.join("judge")
                    .join("keys")
                    .join("judge_evidence_key.priv"),
            );
            candidates.push(gp.join("keys").join("judge_evidence_key.priv"));
        }
    }
    candidates.push(PathBuf::from("./keys/judge_evidence_key.priv"));
    candidates.push(PathBuf::from("../keys/judge_evidence_key.priv"));
    candidates.push(PathBuf::from("./judge/keys/judge_evidence_key.priv"));
    candidates.push(PathBuf::from("../judge/keys/judge_evidence_key.priv"));
    if let Ok(exe) = env::current_exe() {
        if let Some(parent) = exe.parent() {
            candidates.push(parent.join("judge_evidence_key.priv"));
            candidates.push(parent.join("keys").join("judge_evidence_key.priv"));
            if let Some(gp) = parent.parent() {
                candidates.push(gp.join("keys").join("judge_evidence_key.priv"));
            }
        }
    }
    for c in candidates {
        if c.exists() && c.is_file() {
            if let Ok(hex_str) = fs::read_to_string(&c) {
                if let Ok(bytes) = hex::decode(hex_str.trim()) {
                    if bytes.len() >= 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes[..32]);
                        return Some(EvidenceEncryptionKeypair::from_bytes(arr));
                    }
                }
            }
        }
    }
    None
}

#[tauri::command]
fn pick_evidence_file() -> Option<String> {
    rfd::FileDialog::new()
        .set_title("Select Participant Evidence Archive or Database")
        .add_filter("Warmac Archive & SQLite", &["warmac", "sqlite", "db"])
        .pick_file()
        .map(|p| p.display().to_string())
}

#[tauri::command]
fn pick_key_file() -> Option<String> {
    rfd::FileDialog::new()
        .set_title("Select Judge Private Key")
        .add_filter("Private Key", &["priv", "key", "txt"])
        .pick_file()
        .map(|p| p.display().to_string())
}

#[tauri::command]
fn verify_evidence_db(
    db_path: String,
    key_path: Option<String>,
) -> Result<AuditReportResponse, String> {
    let p = PathBuf::from(&db_path);
    if !p.exists() {
        return Err(format!(
            "Evidence database or archive file not found: {db_path}"
        ));
    }

    let judge_keypair =
        locate_judge_key(key_path, &p).unwrap_or_else(EvidenceEncryptionKeypair::generate);
    let policy = MonitoringPolicy::default();
    let verifier = ForensicVerifier::new(policy, judge_keypair);

    let is_warmac = p
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.eq_ignore_ascii_case("warmac"))
        .unwrap_or(false)
        || {
            if let Ok(mut f) = fs::File::open(&p) {
                use std::io::Read;
                let mut magic = [0u8; 8];
                f.read_exact(&mut magic).is_ok() && &magic == warm_storage::WARMAC_MAGIC
            } else {
                false
            }
        };

    let report = if is_warmac {
        verifier
            .audit_warmac_archive(&p)
            .map_err(|e| e.to_string())?
    } else {
        let store = SqliteAuditStore::open(&p).map_err(|e| e.to_string())?;
        let (contest_uuid, participant_id) = if let Some(parent) = p.parent() {
            if let Ok(manifest) = warm_storage::verify_export_package(parent) {
                (manifest.contest_uuid, manifest.participant_id)
            } else if let Ok(events) = store.get_all_events() {
                if let Some(first) = events.first() {
                    (first.contest_uuid, first.participant_id.clone())
                } else {
                    (Uuid::nil(), "participant".to_string())
                }
            } else {
                (Uuid::nil(), "participant".to_string())
            }
        } else {
            (Uuid::nil(), "participant".to_string())
        };
        verifier
            .audit_store(&store, &contest_uuid, &participant_id)
            .map_err(|e| e.to_string())?
    };

    let stats = DeterministicAuditEngine::compute_stats(&report);
    let ai = LocalAiSummarizer::summarize(&report);

    Ok(AuditReportResponse {
        verdict: format!("{}", report.classification),
        participant_id: report.participant_id,
        total_events: report.total_events as usize,
        violations: report
            .findings
            .iter()
            .map(|f| f.description.clone())
            .collect(),
        summary_text: format!(
            "Total events: {}. Critical findings: {}. Warning findings: {}. Processing time: {}ms.",
            stats.total_events,
            stats.critical_findings_count,
            stats.warning_findings_count,
            stats.processing_time_ms
        ),
        ai_advisory: format!(
            "Verdict: {}. Facts: {:?}. Inferences: {:?}",
            ai.verdict, ai.verified_facts, ai.contextual_inferences
        ),
        authenticated_account_id: report.authenticated_account_id.map(|u| u.to_string()),
        declared_log_name: report.declared_log_name,
        participation_mode: format!("{:?}", report.participation_mode),
        screenshots: report.screenshots,
    })
}

fn run_cli(args: &[String]) {
    if args.len() > 1 && args[1] == "verify-manifest" {
        let manifest_path = args
            .get(2)
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("./dist/gocup-1/manifests/contest_manifest.json"));
        let sig_path = args
            .get(3)
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("./dist/gocup-1/manifests/contest_manifest.json.sig"));
        let pk_path = args.get(4).map(PathBuf::from).unwrap_or_else(|| {
            PathBuf::from("./dist/gocup-1/configuration/manifest_signing_key.pub")
        });

        println!("[*] Verifying Contest Manifest digital signature...");
        println!("    Manifest:   {}", manifest_path.display());
        println!("    Signature:  {}", sig_path.display());
        println!("    Public Key: {}", pk_path.display());

        if !manifest_path.exists() || !sig_path.exists() || !pk_path.exists() {
            eprintln!("[ERROR] One or more manifest/signature/key files not found.");
            std::process::exit(1);
        }

        let manifest_bytes = fs::read(&manifest_path).expect("Failed to read manifest file");
        let sig_hex = fs::read_to_string(&sig_path).expect("Failed to read signature file");
        let pk_hex = fs::read_to_string(&pk_path).expect("Failed to read public key file");

        match verify_signature_hex(&pk_hex, &manifest_bytes, &sig_hex) {
            Ok(()) => println!("\n[OK] Manifest digital signature is VALID and authentic!"),
            Err(e) => {
                eprintln!("\n[FAILED] Manifest signature verification failed: {e}");
                std::process::exit(1);
            }
        }
    } else if args.len() > 1 && args[1] == "audit" {
        let db_path = args
            .get(2)
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("./participant_audit.sqlite"));

        println!("[*] Opening audit evidence storage: {}", db_path.display());
        let store = match SqliteAuditStore::open(&db_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[ERROR] Failed to open audit database: {e}");
                std::process::exit(1);
            }
        };

        let dummy_keypair = EvidenceEncryptionKeypair::generate();
        let policy = MonitoringPolicy::default();
        let verifier = ForensicVerifier::new(policy, dummy_keypair);
        let contest_uuid = Uuid::nil();
        let participant_id = "team-42";

        let report = match verifier.audit_store(&store, &contest_uuid, participant_id) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[ERROR] Audit verification failed: {e}");
                std::process::exit(1);
            }
        };

        let stats = DeterministicAuditEngine::compute_stats(&report);
        let ai = LocalAiSummarizer::summarize(&report);

        println!("\n[FORENSIC AUDIT REPORT]");
        println!("    Participant:      {}", report.participant_id);
        println!("    Classification:   {}", report.classification);
        println!("    Hash Chain Valid: {}", report.hash_chain_verified);
        println!("    Total Events:     {}", stats.total_events);
        println!("    Critical Alerts:  {}", stats.critical_findings_count);
        println!("\n[AI ADVISORY SUMMARY]");
        println!("    AI Verdict:       {}", ai.verdict);
        for fact in &ai.verified_facts {
            println!("    - FACT: {fact}");
        }
        for inf in &ai.contextual_inferences {
            println!("    - INFERENCE: {inf}");
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() > 1 && (args[1] == "verify-manifest" || args[1] == "audit") {
        run_cli(&args);
    } else if args.len() > 1 && (args[1] == "--help" || args[1] == "-h") {
        println!("Warm-AntiCheat Judge Verifier");
        println!("Usage:");
        println!("  warm_judge_app verify-manifest [MANIFEST] [SIGNATURE] [PUBKEY]");
        println!("  warm_judge_app audit [DATABASE_PATH]");
        println!("  warm_judge_app [ui]");
    } else {
        tauri::Builder::default()
            .invoke_handler(tauri::generate_handler![
                get_judge_version,
                verify_manifest_file,
                verify_evidence_db,
                check_duplicate_accounts,
                pick_evidence_file,
                pick_key_file
            ])
            .run(tauri::generate_context!())
            .expect("Failed to run Warm-AntiCheat Judge Verifier Desktop Application");
    }
}
