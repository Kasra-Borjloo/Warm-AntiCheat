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

    let build_config = ContestBuildConfig {
        title: contest_title.to_string(),
        organizer: organizer_name.to_string(),
        description: "Official National Algorithmic Championship".to_string(),
        start_time: Some(start_time),
        end_time: Some(end_time),
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
        participation_mode: warm_core::ParticipationMode::NoAccounts,
        account_count: 0,
    };

    let bundle = generate_contest_distribution(&build_config)
        .expect("Contest Builder must generate distribution package");

    assert_eq!(bundle.contest_id, "gocup-1");
    assert!(bundle.root_dir.exists());

    let manifest_file = bundle.root_dir.join("manifests/contest_manifest.json");
    let sig_file = bundle.root_dir.join("manifests/contest_manifest.json.sig");
    let pubkey_file = bundle
        .root_dir
        .join("configuration/manifest_signing_key.pub");

    let manifest_bytes = fs::read(&manifest_file).unwrap();
    let sig_hex = fs::read_to_string(&sig_file).unwrap();
    let pubkey_hex = fs::read_to_string(&pubkey_file).unwrap();

    assert!(verify_signature_hex(&pubkey_hex, &manifest_bytes, &sig_hex).is_ok());

    let participant_id = "team-42";
    let contest_uuid = bundle.signed_manifest.manifest.contest.uuid;
    let participant_db_path = temp_root.join("team42_local.sqlite");

    let store_clean = SqliteAuditStore::open(&participant_db_path).unwrap();
    let mut tracker_clean = HashChainTracker::new(contest_uuid, participant_id);
    let mut session_clean = CompetitionSession::new("gocup-1", participant_id).unwrap();
    session_clean.start().unwrap();

    let judge_pk_hex =
        fs::read_to_string(bundle.root_dir.join("configuration/judge_evidence_key.pub")).unwrap();
    let judge_pk_bytes = hex::decode(judge_pk_hex.trim()).unwrap();
    let mut judge_pk_arr = [0u8; 32];
    judge_pk_arr.copy_from_slice(&judge_pk_bytes);
    let judge_public_key = x25519_dalek::PublicKey::from(judge_pk_arr);

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

    let verified_pkg =
        verify_export_package(&usb_export_dir).expect("Package integrity verification");
    assert_eq!(verified_pkg.total_events, 10);
    assert_eq!(verified_pkg.participant_id, "team-42");

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

    let cheater_db_path = temp_root.join("cheater_local.sqlite");
    let store_cheater = SqliteAuditStore::open(&cheater_db_path).unwrap();
    let mut tracker_cheater = HashChainTracker::new(contest_uuid, "team-cheater");

    let proc_payload = ProcessEventPayload {
        pid: 9988,
        name: "ollama.exe".to_string(),
        path: Some("C:\\tools\\ollama.exe".to_string()),
        cmdline: Some("ollama run codellama".to_string()),
        action: ProcessAction::Started,
        screenshot_attachment: None,
        listening_ports: vec![11434],
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

    let _ = fs::remove_dir_all(temp_root);
}

#[test]
fn test_end_to_end_compiler_audit_and_judge_verification() {
    let temp_root = std::env::temp_dir().join(format!("warm_int_comp_{}", Uuid::new_v4()));
    let dist_root = temp_root.join("dist");
    let _ = fs::create_dir_all(&dist_root);

    let start_time = Utc::now();
    let end_time = start_time + chrono::Duration::hours(4);
    let build_config = ContestBuildConfig {
        title: "GOCUP C++ Championship".to_string(),
        organizer: "Sharif Algorithm Guild".to_string(),
        description: "Official Competitive Programming Contest with Built-in Compiler".to_string(),
        start_time: Some(start_time),
        end_time: Some(end_time),
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
        participation_mode: warm_core::ParticipationMode::NoAccounts,
        account_count: 0,
    };

    let bundle = generate_contest_distribution(&build_config).expect("Generate contest bundle");
    assert!(bundle.signed_manifest.manifest.policy.enable_cpp_compiler);
    assert!(bundle
        .root_dir
        .join("client/toolchain/toolchain_manifest.json")
        .exists());

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

    let payload = if let Ok(tc) = warm_compiler::BundledToolchain::locate(None) {
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
        warm_compiler::build_compiler_audit_payload(&comp_res, Some(&exec_res))
    } else {
        warm_events::CompilerEventPayload {
            source_path: "solution.cpp".to_string(),
            source_sha256: sha256_digest(b"int main() { return 0; }"),
            source_snapshot: "int main() { return 0; }".to_string(),
            compiler_version: "GNU G++ 14.2.0".to_string(),
            toolchain_hash: "mock_tc_hash".to_string(),
            compilation_args: vec!["-std=c++23".to_string(), "-O2".to_string()],
            compilation_start: Utc::now(),
            compilation_end: Utc::now(),
            compiler_exit_code: Some(0),
            compiler_diagnostics: String::new(),
            output_executable_hash: Some("mock_bin_hash".to_string()),
            execution_started: true,
            execution_start: Some(Utc::now()),
            execution_end: Some(Utc::now()),
            program_exit_code: Some(0),
            resource_violations: None,
            execution_error: None,
            executable_args: vec![],
        }
    };
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

    let _ = fs::remove_dir_all(temp_root);
}

#[test]
fn test_end_to_end_account_modes_and_duplicate_detection() {
    let temp_root = std::env::temp_dir().join(format!("warm_acc_e2e_{}", Uuid::new_v4()));
    let dist_root = temp_root.join("dist");
    let _ = fs::create_dir_all(&dist_root);

    let start_time = Utc::now();
    let end_time = start_time + chrono::Duration::hours(4);
    let build_config = ContestBuildConfig {
        title: "GOCUP Account Championship".to_string(),
        organizer: "National Committee".to_string(),
        description: "Contest with Mode B Accounts".to_string(),
        start_time: Some(start_time),
        end_time: Some(end_time),
        prohibited_apps: vec![],
        restricted_domains: vec![],
        supported_platforms: vec!["windows".to_string()],
        branding_theme: "dark".to_string(),
        output_base_dir: dist_root.clone(),
        enable_cpp_compiler: false,
        participation_mode: warm_core::ParticipationMode::GeneratedAccounts,
        account_count: 5,
    };

    let bundle = generate_contest_distribution(&build_config).expect("Generate contest bundle");
    assert_eq!(
        bundle.signed_manifest.manifest.account_mode.mode,
        warm_core::ParticipationMode::GeneratedAccounts
    );
    assert_eq!(
        bundle.signed_manifest.manifest.account_mode.verifiers.len(),
        5
    );

    let judge_csv = bundle.root_dir.join("judge/credentials.csv");
    assert!(judge_csv.exists());
    let csv_content = fs::read_to_string(judge_csv).unwrap();
    let lines: Vec<&str> = csv_content.lines().collect();
    assert_eq!(lines.len(), 6);

    let first_account_line = lines[1];
    let parts: Vec<&str> = first_account_line.split(',').collect();
    let username = parts[2];
    let password = parts[3];
    let account_id: Uuid = parts[4].parse().unwrap();

    let verifier = bundle
        .signed_manifest
        .manifest
        .account_mode
        .verifiers
        .iter()
        .find(|v| v.account_id == account_id)
        .unwrap();

    assert!(warm_crypto::verify_password(
        password,
        &verifier.password_hash
    ));
    assert!(!warm_crypto::verify_password(
        "wrongpass",
        &verifier.password_hash
    ));

    let contest_uuid = bundle.signed_manifest.manifest.contest.uuid;
    let judge_pk_hex =
        fs::read_to_string(bundle.root_dir.join("configuration/judge_evidence_key.pub")).unwrap();
    let judge_pk_bytes = hex::decode(judge_pk_hex.trim()).unwrap();
    let mut judge_pk_arr = [0u8; 32];
    judge_pk_arr.copy_from_slice(&judge_pk_bytes);
    let judge_public_key = x25519_dalek::PublicKey::from(judge_pk_arr);

    let mut reports = Vec::new();

    for session_idx in 1..=2 {
        let participant_id = format!("device-{session_idx}");
        let participant_db = temp_root.join(format!("device_{session_idx}.sqlite"));
        let store = SqliteAuditStore::open(&participant_db).expect("Open store");
        let mut tracker = HashChainTracker::new(contest_uuid, &participant_id);

        let auth_payload = warm_events::AuthEventPayload {
            action: warm_events::AuthAction::LoginSuccess,
            username: username.to_string(),
            account_id: Some(account_id),
            timestamp: Utc::now(),
            note: None,
        };

        let payload_bytes = serde_json::to_vec(&auth_payload).unwrap();
        let payload_hash = sha256_digest(&payload_bytes);
        let now = Utc::now();
        let (seq, prev_h, curr_h) =
            tracker.step(&now.to_rfc3339(), EventCategory::Auth, &payload_hash);
        let aad = format!("{}:{}:{}", contest_uuid, participant_id, seq).into_bytes();
        let sealed =
            seal_asymmetric_payload(&judge_public_key, &contest_uuid, &payload_bytes, &aad)
                .unwrap();

        store
            .record_event(
                seq,
                Uuid::new_v4(),
                contest_uuid,
                &participant_id,
                Uuid::new_v4(),
                now,
                EventCategory::Auth,
                &sealed,
                &payload_hash,
                &prev_h,
                &curr_h,
            )
            .unwrap();

        let judge_priv_hex = fs::read_to_string(&bundle.judge_private_key_path).unwrap();
        let judge_priv_bytes = hex::decode(judge_priv_hex.trim()).unwrap();
        let mut judge_priv_arr = [0u8; 32];
        judge_priv_arr.copy_from_slice(&judge_priv_bytes);
        let judge_keypair = EvidenceEncryptionKeypair::from_bytes(judge_priv_arr);

        let verifier = ForensicVerifier::new(
            bundle.signed_manifest.manifest.policy.clone(),
            judge_keypair,
        );
        let report = verifier
            .audit_store(&store, &contest_uuid, &participant_id)
            .expect("Forensic audit");

        assert_eq!(report.authenticated_account_id, Some(account_id));
        reports.push(report);
    }

    let dup_findings = warm_verifier::detect_duplicate_account_sessions(&reports);
    assert_eq!(dup_findings.len(), 1);
    assert_eq!(
        dup_findings[0].severity,
        warm_verifier::FindingSeverity::Critical
    );
    assert!(dup_findings[0]
        .title
        .contains("Duplicate Account ID Detected"));

    let sanitized = warm_core::sanitize_log_name("Kasra_Solution_1").unwrap();
    assert_eq!(sanitized, "Kasra_Solution_1");
    assert!(warm_core::sanitize_log_name("../traversal/path").is_err());

    let _ = fs::remove_dir_all(temp_root);
}

#[test]
fn test_end_to_end_usb_export_and_mode_a_b_verification() {
    let temp_root = std::env::temp_dir().join(format!("warm_usb_e2e_{}", Uuid::new_v4()));
    let dist_root = temp_root.join("dist");
    let _ = fs::create_dir_all(&dist_root);

    let build_config = ContestBuildConfig {
        title: "USB Automated Contest".to_string(),
        organizer: "Olympic Computing Committee".to_string(),
        description: "Contest with USB Token and Generated Accounts".to_string(),
        start_time: Some(Utc::now()),
        end_time: Some(Utc::now() + Duration::hours(4)),
        prohibited_apps: vec!["ollama.exe".to_string()],
        restricted_domains: vec!["restricted.internal".to_string()],
        supported_platforms: vec!["windows".to_string()],
        branding_theme: "dark".to_string(),
        output_base_dir: dist_root.clone(),
        enable_cpp_compiler: false,
        participation_mode: warm_core::ParticipationMode::GeneratedAccounts,
        account_count: 3,
    };

    let bundle = generate_contest_distribution(&build_config).unwrap();
    let csv_file = dist_root
        .join(&bundle.contest_id)
        .join("judge/credentials.csv");
    let csv_content = fs::read_to_string(&csv_file).unwrap();
    let lines: Vec<&str> = csv_content.lines().collect();
    assert_eq!(lines.len(), 4);

    let v0 = &bundle.signed_manifest.manifest.account_mode.verifiers[0];
    let db_path = temp_root.join("participant_usb.sqlite");
    let store = SqliteAuditStore::open(&db_path).unwrap();

    let contest_uuid = bundle.signed_manifest.manifest.contest.uuid;
    let participant_id = v0.username.clone();
    let mut tracker = HashChainTracker::new(contest_uuid, &participant_id);
    let session_id = Uuid::new_v4();

    let judge_pk_bytes =
        hex::decode(&bundle.signed_manifest.manifest.judge_public_key_hex).unwrap();
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&judge_pk_bytes);
    let judge_public_key = warm_crypto::X25519PublicKey::from(pk_arr);

    let auth_payload = warm_events::AuthEventPayload {
        action: warm_events::AuthAction::LoginSuccess,
        username: participant_id.clone(),
        account_id: Some(v0.account_id),
        timestamp: Utc::now(),
        note: Some("Argon2id credential check".to_string()),
    };
    let auth_json = serde_json::to_vec(&auth_payload).unwrap();
    let auth_hash = sha256_digest(&auth_json);
    let now = Utc::now();
    let (seq, prev_h, curr_h) = tracker.step(&now.to_rfc3339(), EventCategory::Auth, &auth_hash);
    let aad = format!("{}:{}:{}", contest_uuid, participant_id, seq).into_bytes();
    let sealed =
        seal_asymmetric_payload(&judge_public_key, &contest_uuid, &auth_json, &aad).unwrap();

    store
        .record_event(
            seq,
            Uuid::new_v4(),
            contest_uuid,
            &participant_id,
            session_id,
            now,
            EventCategory::Auth,
            &sealed,
            &auth_hash,
            &prev_h,
            &curr_h,
        )
        .unwrap();

    store.checkpoint().unwrap();

    let usb_token_file = dist_root
        .join(&bundle.contest_id)
        .join("judge/usb_token/warm_export_auth.token");
    let token_raw = fs::read_to_string(&usb_token_file).unwrap();
    let signed_token: warm_builder_core::SignedExportAuthToken =
        serde_json::from_str(&token_raw).unwrap();
    assert!(signed_token
        .verify(&bundle.signed_manifest.manifest.manifest_signing_key_pub_hex)
        .is_ok());
    assert_eq!(signed_token.token.contest_id, bundle.contest_id);
    assert_eq!(
        signed_token.token.purpose,
        "CONTEST_LOG_EXPORT_AUTHORIZATION"
    );

    let usb_root = temp_root.join("simulated_usb");
    let target_dir = usb_root
        .join("warm_logs")
        .join(format!("{}_{}", bundle.contest_id, participant_id));
    fs::create_dir_all(&target_dir).unwrap();

    let (last_seq, last_h) = store.get_latest_event_info().unwrap().unwrap();
    let genesis_h = warm_crypto::compute_genesis_hash(&contest_uuid, &participant_id);
    export_evidence_package(
        &db_path,
        &target_dir,
        contest_uuid,
        &participant_id,
        session_id,
        last_seq,
        &last_h,
        &genesis_h,
    )
    .unwrap();

    let verified_export = verify_export_package(&target_dir).unwrap();
    assert_eq!(verified_export.total_events, 1);
    assert_eq!(verified_export.participant_id, participant_id);

    let judge_priv_hex = fs::read_to_string(&bundle.judge_private_key_path).unwrap();
    let judge_priv_bytes = hex::decode(judge_priv_hex.trim()).unwrap();
    let mut judge_priv_arr = [0u8; 32];
    judge_priv_arr.copy_from_slice(&judge_priv_bytes);
    let judge_keypair = EvidenceEncryptionKeypair::from_bytes(judge_priv_arr);

    let verifier = ForensicVerifier::new(
        bundle.signed_manifest.manifest.policy.clone(),
        judge_keypair,
    );
    let exported_store = SqliteAuditStore::open(target_dir.join("evidence.sqlite")).unwrap();
    let report = verifier
        .audit_store(&exported_store, &contest_uuid, &participant_id)
        .unwrap();

    assert_eq!(
        report.participation_mode,
        warm_core::ParticipationMode::GeneratedAccounts
    );
    assert_eq!(report.authenticated_account_id, Some(v0.account_id));
    assert!(report.declared_log_name.is_none());
    assert_eq!(report.classification, VerdictClassification::Safe);

    let _ = fs::remove_dir_all(temp_root);
}

#[test]
fn test_end_to_end_crash_recovery_and_warmac_container() {
    let temp_root = std::env::temp_dir().join(format!("warm_recovery_warmac_{}", Uuid::new_v4()));
    fs::create_dir_all(&temp_root).unwrap();

    let build_config = ContestBuildConfig {
        title: "Resilience Cup".to_string(),
        organizer: "Olympic Computing Committee".to_string(),
        description: "Contest resilience & container test".to_string(),
        start_time: Some(Utc::now()),
        end_time: Some(Utc::now() + Duration::hours(3)),
        prohibited_apps: vec!["ollama.exe".to_string()],
        restricted_domains: vec!["chatgpt.com".to_string()],
        supported_platforms: vec!["windows".to_string(), "linux".to_string()],
        branding_theme: "dark".to_string(),
        output_base_dir: temp_root.join("dist"),
        enable_cpp_compiler: true,
        participation_mode: warm_core::ParticipationMode::NoAccounts,
        account_count: 0,
    };

    let bundle = generate_contest_distribution(&build_config).unwrap();
    let contest_uuid = bundle.signed_manifest.manifest.contest.uuid;
    let participant_id = "participant-recover-01";
    let db_path = temp_root.join("session_data").join("audit.sqlite");
    fs::create_dir_all(db_path.parent().unwrap()).unwrap();

    let judge_pk_bytes =
        hex::decode(&bundle.signed_manifest.manifest.judge_public_key_hex).unwrap();
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&judge_pk_bytes);
    let judge_public_key = warm_crypto::X25519PublicKey::from(pk_arr);

    let session_id = Uuid::new_v4();

    {
        let store = SqliteAuditStore::open(&db_path).unwrap();
        let mut tracker = HashChainTracker::new(contest_uuid, participant_id);

        for i in 1..=5 {
            let payload = format!("{{\"action\":\"initial_stage_{i}\"}}").into_bytes();
            let payload_hash = sha256_digest(&payload);
            let now = Utc::now();
            let (seq, prev_h, curr_h) =
                tracker.step(&now.to_rfc3339(), EventCategory::Process, &payload_hash);
            let aad = format!("{}:{}:{}", contest_uuid, participant_id, seq).into_bytes();
            let sealed =
                seal_asymmetric_payload(&judge_public_key, &contest_uuid, &payload, &aad).unwrap();
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
                    &prev_h,
                    &curr_h,
                )
                .unwrap();
        }
        store.checkpoint().unwrap();
    }

    let fake_bmp = vec![
        0x42, 0x4D, 0x46, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00, 0x28,
        0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x18, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0xFF, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00,
    ];

    let recovered_store = SqliteAuditStore::open(&db_path).unwrap();
    let recovery_info = recovered_store.get_session_recovery_info().unwrap();
    assert!(recovery_info.is_some());
    let rec_info = recovery_info.unwrap();
    assert_eq!(rec_info.contest_uuid, contest_uuid);
    assert_eq!(rec_info.participant_id, participant_id);
    assert_eq!(rec_info.session_id, session_id);
    let rec_sid = rec_info.session_id;
    assert_eq!(rec_info.last_sequence, 5);

    let mut resumed_tracker = HashChainTracker::resume(
        contest_uuid,
        participant_id,
        rec_info.last_sequence,
        &rec_info.last_hash,
    );

    let int_payload =
        warm_platform::LifecycleTracker::on_monitoring_interrupted("Power loss or client restart");
    let int_json = serde_json::to_vec(&int_payload).unwrap();
    let int_hash = sha256_digest(&int_json);
    let now = Utc::now();
    let (seq6, prev6, curr6) =
        resumed_tracker.step(&now.to_rfc3339(), EventCategory::SystemLifecycle, &int_hash);
    let aad6 = format!("{}:{}:{}", contest_uuid, participant_id, seq6).into_bytes();
    let sealed6 =
        seal_asymmetric_payload(&judge_public_key, &contest_uuid, &int_json, &aad6).unwrap();
    recovered_store
        .record_event(
            seq6,
            Uuid::new_v4(),
            contest_uuid,
            participant_id,
            rec_sid,
            now,
            EventCategory::SystemLifecycle,
            &sealed6,
            &int_hash,
            &prev6,
            &curr6,
        )
        .unwrap();

    let rec_payload = warm_platform::LifecycleTracker::on_monitoring_recovered(
        "Session state restored from SQLite WAL",
    );
    let rec_json = serde_json::to_vec(&rec_payload).unwrap();
    let rec_hash = sha256_digest(&rec_json);
    let now = Utc::now();
    let (seq7, prev7, curr7) =
        resumed_tracker.step(&now.to_rfc3339(), EventCategory::SystemLifecycle, &rec_hash);
    let aad7 = format!("{}:{}:{}", contest_uuid, participant_id, seq7).into_bytes();
    let sealed7 =
        seal_asymmetric_payload(&judge_public_key, &contest_uuid, &rec_json, &aad7).unwrap();
    recovered_store
        .record_event(
            seq7,
            Uuid::new_v4(),
            contest_uuid,
            participant_id,
            rec_sid,
            now,
            EventCategory::SystemLifecycle,
            &sealed7,
            &rec_hash,
            &prev7,
            &curr7,
        )
        .unwrap();

    let att_id = Uuid::new_v4();
    let att_ref = warm_events::EvidenceAttachmentRef {
        attachment_id: att_id,
        filename: "suspicious_ollama.bmp".to_string(),
        mime_type: "image/bmp".to_string(),
        sha256_hash: sha256_digest(&fake_bmp),
        size_bytes: fake_bmp.len() as u64,
        captured_at: Utc::now(),
        reason: "Prohibited AI process detected: ollama.exe".to_string(),
    };

    let proc_payload = ProcessEventPayload {
        pid: 7788,
        name: "ollama.exe".to_string(),
        path: Some("C:\\bin\\ollama.exe".to_string()),
        cmdline: Some("ollama serve".to_string()),
        action: ProcessAction::Started,
        screenshot_attachment: Some(att_ref),
        listening_ports: vec![11434],
    };
    let proc_json = serde_json::to_vec(&proc_payload).unwrap();
    let proc_hash = sha256_digest(&proc_json);
    let now = Utc::now();
    let (seq8, prev8, curr8) =
        resumed_tracker.step(&now.to_rfc3339(), EventCategory::Process, &proc_hash);
    let aad8 = format!("{}:{}:{}", contest_uuid, participant_id, seq8).into_bytes();
    let sealed8 =
        seal_asymmetric_payload(&judge_public_key, &contest_uuid, &proc_json, &aad8).unwrap();
    recovered_store
        .record_event(
            seq8,
            Uuid::new_v4(),
            contest_uuid,
            participant_id,
            rec_sid,
            now,
            EventCategory::Process,
            &sealed8,
            &proc_hash,
            &prev8,
            &curr8,
        )
        .unwrap();

    recovered_store.checkpoint().unwrap();

    let warmac_path = temp_root.join(format!("{}_{}.warmac", bundle.contest_id, participant_id));
    let raw_manifest = serde_json::to_vec(&bundle.signed_manifest.manifest).unwrap();
    let attachments = vec![("suspicious_ollama.bmp".to_string(), fake_bmp)];

    warm_storage::create_warmac_package(
        &warmac_path,
        &raw_manifest,
        &bundle.signed_manifest.signature_hex,
        &bundle.signed_manifest.manifest.manifest_signing_key_pub_hex,
        &judge_public_key,
        &recovered_store,
        contest_uuid,
        participant_id,
        rec_sid,
        None,
        &attachments,
    )
    .unwrap();

    assert!(warmac_path.exists());
    let inspected = warm_storage::inspect_warmac_file(&warmac_path).unwrap();
    assert_eq!(inspected.0, contest_uuid);
    assert_eq!(inspected.1, rec_sid);
    assert_eq!(inspected.2, participant_id);
    assert!(inspected.3 > 100);

    let judge_priv_hex = fs::read_to_string(&bundle.judge_private_key_path).unwrap();
    let judge_priv_bytes = hex::decode(judge_priv_hex.trim()).unwrap();
    let mut judge_priv_arr = [0u8; 32];
    judge_priv_arr.copy_from_slice(&judge_priv_bytes);
    let judge_keypair = EvidenceEncryptionKeypair::from_bytes(judge_priv_arr);

    let verifier = ForensicVerifier::new(
        bundle.signed_manifest.manifest.policy.clone(),
        judge_keypair,
    );

    let report = verifier.audit_warmac_archive(&warmac_path).unwrap();
    assert_eq!(report.contest_uuid, contest_uuid);
    assert_eq!(report.participant_id, participant_id);
    assert_eq!(report.total_events, 8);
    assert!(report.hash_chain_verified);
    assert_eq!(report.classification, VerdictClassification::Unsafe);
    assert!(!report.findings.is_empty());
    assert_eq!(report.screenshots.len(), 1);
    assert_eq!(report.screenshots[0].filename, "suspicious_ollama.bmp");
    assert_eq!(report.screenshots[0].mime_type, "image/bmp");
    assert!(!report.screenshots[0].data_base64.is_empty());

    let _ = fs::remove_dir_all(temp_root);
}
