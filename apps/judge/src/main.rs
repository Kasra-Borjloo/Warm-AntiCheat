//! Warm-AntiCheat Judge Verifier Application Entry Point

use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::PathBuf;
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

#[tauri::command]
fn verify_evidence_db(
    db_path: String,
    key_path: Option<String>,
) -> Result<AuditReportResponse, String> {
    let p = PathBuf::from(&db_path);
    if !p.exists() {
        return Err(format!("Evidence database file not found: {db_path}"));
    }

    let store = SqliteAuditStore::open(&p).map_err(|e| e.to_string())?;

    let judge_keypair = if let Some(kp) = key_path {
        let hex_str = fs::read_to_string(&kp).map_err(|e| e.to_string())?;
        let bytes = hex::decode(hex_str.trim()).map_err(|e| e.to_string())?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes[..32]);
        EvidenceEncryptionKeypair::from_bytes(arr)
    } else {
        EvidenceEncryptionKeypair::generate()
    };

    let policy = MonitoringPolicy::default();
    let verifier = ForensicVerifier::new(policy, judge_keypair);
    let contest_uuid = Uuid::nil();
    let participant_id = "participant";

    let report = verifier
        .audit_store(&store, &contest_uuid, participant_id)
        .map_err(|e| e.to_string())?;

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
        // Run Desktop GUI via Tauri
        tauri::Builder::default()
            .invoke_handler(tauri::generate_handler![
                get_judge_version,
                verify_manifest_file,
                verify_evidence_db
            ])
            .run(tauri::generate_context!())
            .expect("Failed to run Warm-AntiCheat Judge Verifier Desktop Application");
    }
}
