use chrono::{Duration, Utc};
use std::fs;
use uuid::Uuid;
use warm_audit::{DeterministicAuditEngine, LocalAiSummarizer};
use warm_builder_core::{generate_contest_distribution, ContestBuildConfig};
use warm_core::CompetitionSession;
use warm_crypto::{
    seal_asymmetric_payload, sha256_digest, verify_signature_hex, EvidenceEncryptionKeypair,
};
use warm_events::{EventCategory, ProcessAction, ProcessEventPayload};
use warm_storage::{
    export_evidence_package, verify_export_package, HashChainTracker, SqliteAuditStore,
};
use warm_verifier::{ForensicVerifier, VerdictClassification};

#[test]
fn test_end_to_end_full_contest_lifecycle() {
    let temp_root = std::env::temp_dir().join(format!("warm_e2e_{}", Uuid::new_v4()));
    fs::create_dir_all(&temp_root).expect("Failed to create temp root");

    let contest_title = "GOCUP 1";
    let organizer_name = "Sharif University Computer Society";
    let start_time = Utc::now();
    let end_time = start_time + Duration::hours(4);

    // =========================================================================
    // STEP 1: CONTEST BUILDER
    // =========================================================================
    let build_config = ContestBuildConfig {
        title: contest_title.to_string(),
        organizer: organizer_name.to_string(),
        description: "Official National Algorithmic Championship".to_string(),
        start_time,
        end_time,
        prohibited_apps: vec!["ollama.exe".to_string(), "lmstudio.exe".to_string()],
        restricted_domains: vec!["chatgpt.com".to_string(), "claude.ai".to_string()],
        supported_platforms: vec![
            "windows".to_string(),
            "linux".to_string(),
            "macos".to_string(),
        ],
        branding_theme: "dark".to_string(),
        output_base_dir: temp_root.join("dist"),
        enable_cpp_compiler: false,
    };

    let bundle = generate_contest_distribution(&build_config)
        .expect("Contest Builder must generate distribution package");

    assert_eq!(bundle.contest_id, "gocup-1");
    assert!(bundle.root_dir.exists());

    // Verify generated manifest signature
    let manifest_file = bundle.root_dir.join("manifests/contest_manifest.json");
    let sig_file = bundle.root_dir.join("manifests/contest_manifest.json.sig");
    let pubkey_file = bundle
        .root_dir
        .join("configuration/manifest_signing_key.pub");

    let manifest_bytes = fs::read(&manifest_file).unwrap();
    let sig_hex = fs::read_to_string(&sig_file).unwrap();
    let pubkey_hex = fs::read_to_string(&pubkey_file).unwrap();

    assert!(verify_signature_hex(&pubkey_hex, &manifest_bytes, &sig_hex).is_ok());

    // =========================================================================
    // STEP 2: PARTICIPANT CLIENT (Clean / SAFE Participant: Team 42)
    // =========================================================================
    let participant_id = "team-42";
    let contest_uuid = bundle.signed_manifest.manifest.contest.uuid;
    let participant_db_path = temp_root.join("team42_local.sqlite");

    let store_clean = SqliteAuditStore::open(&participant_db_path).unwrap();
    let mut tracker_clean = HashChainTracker::new(contest_uuid, participant_id);
    let mut session_clean = CompetitionSession::new("gocup-1", participant_id).unwrap();
    session_clean.start().unwrap();

    // Load judge public key from client configuration
    let judge_pk_hex =
        fs::read_to_string(bundle.root_dir.join("configuration/judge_evidence_key.pub")).unwrap();
    let judge_pk_bytes = hex::decode(judge_pk_hex.trim()).unwrap();
    let mut judge_pk_arr = [0u8; 32];
    judge_pk_arr.copy_from_slice(&judge_pk_bytes);
    let judge_public_key = x25519_dalek::PublicKey::from(judge_pk_arr);

    // Record benign events: Launch, Benign Code Editor Process, Heartbeat
    for i in 1..=10 {
        let payload =
            format!("{{\"action\":\"benign_activity_{i}\",\"proc\":\"code.exe\"}}").into_bytes();
        let payload_hash = sha256_digest(&payload);
        let now = Utc::now();
        let (seq, prev_h, curr_h) =
            tracker_clean.step(&now.to_rfc3339(), EventCategory::Process, &payload_hash);

        let aad = format!("{}:{}:{}", contest_uuid, participant_id, seq).into_bytes();
        let sealed =
            seal_asymmetric_payload(&judge_public_key, &contest_uuid, &payload, &aad).unwrap();

        store_clean
            .record_event(
                seq,
                Uuid::new_v4(),
                contest_uuid,
                participant_id,
                session_clean.session_id,
                now,
                EventCategory::Process,
                &sealed,
                &payload_hash,
                &prev_h,
                &curr_h,
            )
            .unwrap();
    }

    session_clean.conclude().unwrap();
    store_clean.checkpoint().unwrap();

    // =========================================================================
    // STEP 3: USB EVIDENCE EXPORT
    // =========================================================================
    let usb_export_dir = temp_root.join("usb_drive/team-42.warm-evidence");
    let (last_seq, last_h) = store_clean.get_latest_event_info().unwrap().unwrap();
    let genesis_h = warm_crypto::compute_genesis_hash(&contest_uuid, participant_id);

    export_evidence_package(
        &participant_db_path,
        &usb_export_dir,
        contest_uuid,
        participant_id,
        session_clean.session_id,
        last_seq,
        &genesis_h,
        &last_h,
    )
    .expect("USB evidence export should succeed");

    // Verify exported package format
    let verified_pkg =
        verify_export_package(&usb_export_dir).expect("Package integrity verification");
    assert_eq!(verified_pkg.total_events, 10);
    assert_eq!(verified_pkg.participant_id, "team-42");

    // =========================================================================
    // STEP 4: JUDGE VERIFIER FORENSIC AUDIT (SAFE CASE)
    // =========================================================================
    // Judge loads private decryption key from quarantined judge/keys/
    let judge_priv_hex = fs::read_to_string(&bundle.judge_private_key_path).unwrap();
    let judge_priv_bytes = hex::decode(judge_priv_hex.trim()).unwrap();
    let mut judge_priv_arr = [0u8; 32];
    judge_priv_arr.copy_from_slice(&judge_priv_bytes);
    let judge_keypair = EvidenceEncryptionKeypair::from_bytes(judge_priv_arr);

    let judge_store = SqliteAuditStore::open(usb_export_dir.join("evidence.sqlite")).unwrap();
    let verifier = ForensicVerifier::new(
        bundle.signed_manifest.manifest.policy.clone(),
        judge_keypair,
    );

    let clean_report = verifier
        .audit_store(&judge_store, &contest_uuid, "team-42")
        .unwrap();

    assert_eq!(clean_report.classification, VerdictClassification::Safe);
    assert_eq!(clean_report.total_events, 10);
    assert!(clean_report.hash_chain_verified);
    assert!(clean_report.findings.is_empty());

    let clean_stats = DeterministicAuditEngine::compute_stats(&clean_report);
    assert_eq!(clean_stats.critical_findings_count, 0);

    let clean_ai = LocalAiSummarizer::summarize(&clean_report);
    assert_eq!(clean_ai.verdict, "SAFE");
    assert!(clean_ai.human_review_mandatory);

    // =========================================================================
    // STEP 5: JUDGE VERIFIER (UNSAFE CASE: Prohibited Ollama detected)
    // =========================================================================
    let cheater_db_path = temp_root.join("cheater_local.sqlite");
    let store_cheater = SqliteAuditStore::open(&cheater_db_path).unwrap();
    let mut tracker_cheater = HashChainTracker::new(contest_uuid, "team-cheater");

    // Record prohibited Ollama event
    let proc_payload = ProcessEventPayload {
        pid: 9988,
        name: "ollama.exe".to_string(),
        path: Some("C:\\tools\\ollama.exe".to_string()),
        cmdline: Some("ollama run codellama".to_string()),
        action: ProcessAction::Started,
    };
    let payload_bytes = serde_json::to_vec(&proc_payload).unwrap();
    let payload_h = sha256_digest(&payload_bytes);
    let now = Utc::now();
    let (seq_c, prev_h_c, curr_h_c) =
        tracker_cheater.step(&now.to_rfc3339(), EventCategory::Process, &payload_h);

    let aad_c = format!("{}:{}:{}", contest_uuid, "team-cheater", seq_c).into_bytes();
    let sealed_c =
        seal_asymmetric_payload(&judge_public_key, &contest_uuid, &payload_bytes, &aad_c).unwrap();

    store_cheater
        .record_event(
            seq_c,
            Uuid::new_v4(),
            contest_uuid,
            "team-cheater",
            Uuid::new_v4(),
            now,
            EventCategory::Process,
            &sealed_c,
            &payload_h,
            &prev_h_c,
            &curr_h_c,
        )
        .unwrap();

    let cheater_keypair = EvidenceEncryptionKeypair::from_bytes(judge_priv_arr);
    let verifier_cheater =
        ForensicVerifier::new(bundle.signed_manifest.manifest.policy, cheater_keypair);
    let cheater_report = verifier_cheater
        .audit_store(&store_cheater, &contest_uuid, "team-cheater")
        .unwrap();

    assert_eq!(cheater_report.classification, VerdictClassification::Unsafe);
    assert!(!cheater_report.findings.is_empty());
    assert_eq!(
        cheater_report.findings[0].severity,
        warm_verifier::FindingSeverity::Critical
    );
    assert!(cheater_report.findings[0]
        .description
        .contains("ollama.exe"));

    // Cleanup
    let _ = fs::remove_dir_all(temp_root);
}

#[test]
fn test_end_to_end_compiler_audit_and_judge_verification() {
    let temp_root = std::env::temp_dir().join(format!("warm_int_comp_{}", Uuid::new_v4()));
    let dist_root = temp_root.join("dist");
    let _ = fs::create_dir_all(&dist_root);

    // 1. Organizer configures contest with C++ Compiler Enabled
    let start_time = Utc::now();
    let end_time = start_time + chrono::Duration::hours(4);
    let build_config = ContestBuildConfig {
        title: "GOCUP C++ Championship".to_string(),
        organizer: "Sharif Algorithm Guild".to_string(),
        description: "Official Competitive Programming Contest with Built-in Compiler".to_string(),
        start_time,
        end_time,
        prohibited_apps: vec!["ollama.exe".to_string()],
        restricted_domains: vec!["chatgpt.com".to_string()],
        supported_platforms: vec![
            "windows".to_string(),
            "linux".to_string(),
            "macos".to_string(),
        ],
        branding_theme: "dark".to_string(),
        output_base_dir: dist_root.clone(),
        enable_cpp_compiler: true,
    };

    let bundle = generate_contest_distribution(&build_config).expect("Generate contest bundle");
    assert!(bundle.signed_manifest.manifest.policy.enable_cpp_compiler);
    assert!(bundle
        .root_dir
        .join("client/toolchain/toolchain_manifest.json")
        .exists());

    // 2. Participant uses bundled C++23 compiler
    let participant_id = "contestant-99";
    let contest_uuid = bundle.signed_manifest.manifest.contest.uuid;
    let participant_db = temp_root.join("participant.sqlite");

    let store = SqliteAuditStore::open(&participant_db).expect("Open store");
    let mut tracker = HashChainTracker::new(contest_uuid, participant_id);
    let mut session = CompetitionSession::new("gocup-cpp", participant_id).unwrap();
    session.start().unwrap();

    let judge_pk_hex =
        fs::read_to_string(bundle.root_dir.join("configuration/judge_evidence_key.pub")).unwrap();
    let judge_pk_bytes = hex::decode(judge_pk_hex.trim()).unwrap();
    let mut judge_pk_arr = [0u8; 32];
    judge_pk_arr.copy_from_slice(&judge_pk_bytes);
    let judge_public_key = x25519_dalek::PublicKey::from(judge_pk_arr);

    // Compile C++23 solution
    let tc = warm_compiler::BundledToolchain::locate(None).expect("Bundled toolchain");
    let engine = warm_compiler::CompilerEngine::new(tc);

    let cpp_code = r#"
#include <bits/stdc++.h>
int main() {
    int x;
    if (std::cin >> x) {
        std::cout << "SQUARE=" << (x * x) << std::endl;
    }
    return 0;
}
"#;

    let comp_req = warm_compiler::CompilationRequest {
        source_path: std::path::PathBuf::from("solution.cpp"),
        source_code: Some(cpp_code.to_string()),
        output_dir: None,
        optimization_level: Some("-O2".to_string()),
        standard: Some("-std=c++23".to_string()),
        extra_args: vec!["-pipe".to_string()],
    };

    let comp_res = engine.compile(comp_req).expect("Compile solution.cpp");
    assert!(comp_res.success);

    let exec_res = warm_compiler::ExecutionRunner::execute(warm_compiler::ExecutionRequest {
        binary_path: comp_res.output_binary_path.clone().unwrap(),
        toolchain_bin_dir: Some(engine.toolchain().root_dir.join("bin")),
        stdin_input: Some("9\n".to_string()),
        timeout_ms: 5000,
        args: vec![],
    })
    .expect("Execute solution.cpp");

    assert_eq!(exec_res.stdout.trim(), "SQUARE=81");

    // Cryptographically record Compiler audit event
    let payload = warm_compiler::build_compiler_audit_payload(&comp_res, Some(&exec_res));
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let payload_hash = sha256_digest(&payload_bytes);
    let now = Utc::now();
    let (seq, prev_h, curr_h) =
        tracker.step(&now.to_rfc3339(), EventCategory::Compiler, &payload_hash);
    let aad = format!("{}:{}:{}", contest_uuid, participant_id, seq).into_bytes();
    let sealed =
        seal_asymmetric_payload(&judge_public_key, &contest_uuid, &payload_bytes, &aad).unwrap();

    store
        .record_event(
            seq,
            Uuid::new_v4(),
            contest_uuid,
            participant_id,
            session.session_id,
            now,
            EventCategory::Compiler,
            &sealed,
            &payload_hash,
            &prev_h,
            &curr_h,
        )
        .unwrap();

    session.conclude().unwrap();
    store.checkpoint().unwrap();

    // 3. Judge Verifier Forensics
    let judge_priv_hex = fs::read_to_string(&bundle.judge_private_key_path).unwrap();
    let judge_priv_bytes = hex::decode(judge_priv_hex.trim()).unwrap();
    let mut judge_priv_arr = [0u8; 32];
    judge_priv_arr.copy_from_slice(&judge_priv_bytes);
    let judge_keypair = EvidenceEncryptionKeypair::from_bytes(judge_priv_arr);

    let verifier = ForensicVerifier::new(bundle.signed_manifest.manifest.policy, judge_keypair);
    let report = verifier
        .audit_store(&store, &contest_uuid, participant_id)
        .expect("Forensic audit");

    assert_eq!(report.classification, VerdictClassification::Safe);
    assert_eq!(report.total_events, 1);
    assert!(report.hash_chain_verified);
    assert_eq!(report.timeline[0].category, "Compiler");

    let stats = warm_audit::DeterministicAuditEngine::compute_stats(&report);
    assert_eq!(stats.event_distribution.get("Compiler"), Some(&1));

    let ai_summary = warm_audit::LocalAiSummarizer::summarize(&report);
    assert_eq!(ai_summary.verdict, "SAFE");
    assert!(ai_summary
        .verified_facts
        .iter()
        .any(|f| f.contains("Built-in C++ compiler activity recorded")));

    // Cleanup
    let _ = fs::remove_dir_all(temp_root);
}
