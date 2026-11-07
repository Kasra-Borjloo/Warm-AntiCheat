//! Warm-AntiCheat Judge Verifier Application Entry Point

use std::env;
use std::fs;
use std::path::PathBuf;
use uuid::Uuid;
use warm_audit::{DeterministicAuditEngine, LocalAiSummarizer};
use warm_crypto::{verify_signature_hex, EvidenceEncryptionKeypair};
use warm_policies::MonitoringPolicy;
use warm_storage::SqliteAuditStore;
use warm_verifier::ForensicVerifier;

fn main() {
    let args: Vec<String> = env::args().collect();

    println!("=======================================================");
    println!(
        "   Warm-AntiCheat Judge Verifier v{}",
        env!("CARGO_PKG_VERSION")
    );
    println!("   Offline-First Forensic Verification Engine");
    println!("=======================================================\n");

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
        let key_path = args
            .get(3)
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("./dist/gocup-1/judge/keys/judge_evidence_key.priv"));

        println!("[*] Executing forensic audit on evidence database...");
        println!("    Database:   {}", db_path.display());
        println!("    Key:        {}", key_path.display());

        if !db_path.exists() {
            eprintln!(
                "[ERROR] Audit database file not found at {}",
                db_path.display()
            );
            return;
        }

        let keypair = if key_path.exists() {
            let hex_str = fs::read_to_string(&key_path).expect("Failed to read key file");
            let bytes = hex::decode(hex_str.trim()).expect("Invalid hex in private key");
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            EvidenceEncryptionKeypair::from_bytes(arr)
        } else {
            println!("[WARN] Judge private key file not found at specified path, generating ephemeral session key.");
            EvidenceEncryptionKeypair::generate()
        };

        let store = SqliteAuditStore::open(&db_path).expect("Failed to open audit store");
        let policy = MonitoringPolicy::default();
        let verifier = ForensicVerifier::new(policy, keypair);

        let contest_uuid = Uuid::new_v4();
        let report = verifier
            .audit_store(&store, &contest_uuid, "team-42")
            .expect("Forensic audit failed");

        let stats = DeterministicAuditEngine::compute_stats(&report);
        let ai_summary = LocalAiSummarizer::summarize(&report);

        println!("\n=======================================================");
        println!("   FORENSIC AUDIT REPORT");
        println!("=======================================================");
        println!("Verdict:               {}", report.classification);
        println!("Hash Chain Verified:   {}", report.hash_chain_verified);
        println!("Total Events:          {}", report.total_events);
        println!("Processing Time:       {} ms", stats.processing_time_ms);
        println!("Critical Findings:     {}", stats.critical_findings_count);
        println!("Summary:               {}", report.summary);

        println!("\n[*] Advisory AI Summary:");
        for fact in &ai_summary.verified_facts {
            println!("    [FACT] {}", fact);
        }
        for inf in &ai_summary.contextual_inferences {
            println!("    [INFERENCE] {}", inf);
        }
        for rec in &ai_summary.recommended_actions {
            println!("    [RECOMMENDATION] {}", rec);
        }
    } else {
        println!("Commands:");
        println!("  warm_judge_app verify-manifest [MANIFEST_PATH] [SIG_PATH] [PUBKEY_PATH]");
        println!("  warm_judge_app audit [DB_PATH] [KEY_PATH]\n");
        println!("Web UI assets available at: apps/judge/ui/index.html");
    }
}
