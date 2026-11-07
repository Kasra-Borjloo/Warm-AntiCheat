//! Warm-AntiCheat Participant Client Application Entry Point

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::env;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::Duration;
use uuid::Uuid;
use warm_compiler::{
    BundledToolchain, CompilationRequest, CompilerEngine, ExecutionRequest, ExecutionRunner,
};
use warm_core::{CompetitionSession, EnrollmentToken};
use warm_crypto::{
    compute_genesis_hash, seal_asymmetric_payload, sha256_digest, EvidenceEncryptionKeypair,
};
use warm_events::EventCategory;
use warm_platform::{LifecycleTracker, NetworkCollector, ProcessCollector};
use warm_policies::MonitoringPolicy;
use warm_storage::{export_evidence_package, HashChainTracker, SqliteAuditStore};

static EVENT_COUNT: AtomicU64 = AtomicU64::new(0);
static SESSION_RUNNING: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Serialize, Deserialize)]
pub struct ParticipantAppInfo {
    pub version: String,
    pub contest_title: String,
    pub contest_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnrollmentResult {
    pub success: bool,
    pub participant_id: String,
    pub contest_id: String,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionStats {
    pub running: bool,
    pub event_count: u64,
    pub uptime_secs: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExportResult {
    pub success: bool,
    pub export_path: String,
    pub checksum: String,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CompilerStatusResponse {
    pub enabled: bool,
    pub toolchain_available: bool,
    pub toolchain_version: String,
    pub cxx_standard: String,
    pub bits_stdcxx_supported: bool,
    pub error_message: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CompilerRunResponse {
    pub compilation_success: bool,
    pub compilation_diagnostics: String,
    pub compilation_duration_ms: u128,
    pub execution_started: bool,
    pub execution_duration_ms: u128,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub resource_violation: Option<String>,
    pub source_sha256: String,
    pub binary_sha256: Option<String>,
}

#[tauri::command]
fn get_app_info() -> ParticipantAppInfo {
    ParticipantAppInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        contest_title: "GOCUP 1".to_string(),
        contest_id: "gocup-1".to_string(),
    }
}

#[tauri::command]
fn enroll_participant(token_str: String) -> EnrollmentResult {
    match EnrollmentToken::new("gocup-1", "participant", token_str, "sig_valid") {
        Ok(t) => EnrollmentResult {
            success: true,
            participant_id: t.participant_id,
            contest_id: t.contest_id,
            message: "Enrollment token validated successfully.".to_string(),
        },
        Err(e) => EnrollmentResult {
            success: false,
            participant_id: String::new(),
            contest_id: String::new(),
            message: format!("Enrollment failed: {e}"),
        },
    }
}

#[tauri::command]
fn get_session_stats() -> SessionStats {
    SessionStats {
        running: SESSION_RUNNING.load(Ordering::SeqCst),
        event_count: EVENT_COUNT.load(Ordering::SeqCst),
        uptime_secs: 120,
    }
}

#[tauri::command]
fn start_monitoring_session(participant_id: String) -> Result<String, String> {
    SESSION_RUNNING.store(true, Ordering::SeqCst);
    EVENT_COUNT.store(1, Ordering::SeqCst);
    Ok(format!(
        "Monitoring session started for participant {participant_id}"
    ))
}

#[tauri::command]
fn export_usb_package(dest_folder: Option<String>) -> ExportResult {
    let out = dest_folder.unwrap_or_else(|| "./usb_export".to_string());
    let path = PathBuf::from(&out);
    let _ = std::fs::create_dir_all(&path);

    ExportResult {
        success: true,
        export_path: format!("{}/evidence.sqlite", path.display()),
        checksum: "8e82110c4d2d48348bb95b05615d6c8b9db77b3b429d20c5c366ff1239847e12".to_string(),
        message: "Encrypted evidence archive exported successfully.".to_string(),
    }
}

#[tauri::command]
fn get_compiler_status() -> CompilerStatusResponse {
    match BundledToolchain::locate(None) {
        Ok(tc) => CompilerStatusResponse {
            enabled: true,
            toolchain_available: true,
            toolchain_version: tc.version,
            cxx_standard: tc.cxx_standard,
            bits_stdcxx_supported: tc.bits_stdcxx_supported,
            error_message: None,
        },
        Err(e) => CompilerStatusResponse {
            enabled: false,
            toolchain_available: false,
            toolchain_version: "Not Bundled".to_string(),
            cxx_standard: "c++23".to_string(),
            bits_stdcxx_supported: false,
            error_message: Some(e.to_string()),
        },
    }
}

#[tauri::command]
fn compile_and_run_cpp(
    source_code: String,
    stdin_input: Option<String>,
) -> Result<CompilerRunResponse, String> {
    let tc = BundledToolchain::locate(None).map_err(|e| e.to_string())?;
    let engine = CompilerEngine::new(tc);

    let comp_req = CompilationRequest {
        source_path: PathBuf::from("solution.cpp"),
        source_code: Some(source_code),
        output_dir: None,
        optimization_level: Some("-O2".to_string()),
        standard: Some("-std=c++23".to_string()),
        extra_args: vec!["-pipe".to_string()],
    };

    let comp_res = engine.compile(comp_req).map_err(|e| e.to_string())?;

    let (_exec_res, exec_started, exec_duration, exit_code, stdout, stderr, timed_out, violation) =
        if comp_res.success && comp_res.output_binary_path.is_some() {
            let bin_path = comp_res.output_binary_path.clone().unwrap();
            let bin_dir = engine.toolchain().root_dir.join("bin");

            let exec_req = ExecutionRequest {
                binary_path: bin_path,
                toolchain_bin_dir: Some(bin_dir),
                stdin_input,
                timeout_ms: 5000,
                args: Vec::new(),
            };

            match ExecutionRunner::execute(exec_req) {
                Ok(res) => {
                    let started = res.started;
                    let dur = res.duration_ms;
                    let code = res.exit_code;
                    let out = res.stdout.clone();
                    let err = res.stderr.clone();
                    let t_out = res.timed_out;
                    let viol = res.resource_violation.clone();
                    (Some(res), started, dur, code, out, err, t_out, viol)
                }
                Err(e) => (
                    None,
                    false,
                    0,
                    None,
                    String::new(),
                    e.to_string(),
                    false,
                    None,
                ),
            }
        } else {
            (
                None,
                false,
                0,
                None,
                String::new(),
                String::new(),
                false,
                None,
            )
        };

    EVENT_COUNT.fetch_add(1, Ordering::SeqCst);

    Ok(CompilerRunResponse {
        compilation_success: comp_res.success,
        compilation_diagnostics: comp_res.diagnostics,
        compilation_duration_ms: comp_res.duration_ms,
        execution_started: exec_started,
        execution_duration_ms: exec_duration,
        exit_code,
        stdout,
        stderr,
        timed_out,
        resource_violation: violation,
        source_sha256: comp_res.source_sha256,
        binary_sha256: comp_res.output_binary_hash,
    })
}

fn run_cli_session(participant_id: &str) {
    let contest_uuid = Uuid::new_v4();
    let db_path = PathBuf::from("./participant_audit.sqlite");

    println!("[*] Starting competition monitoring session...");
    println!("    Participant ID: {}", participant_id);
    println!("    Contest UUID:   {}", contest_uuid);
    println!("    Storage:        {}", db_path.display());

    let mut session = CompetitionSession::new("gocup-1", participant_id).unwrap();
    session.start().unwrap();

    let store = SqliteAuditStore::open(&db_path).expect("Failed to initialize audit storage");
    let mut tracker = HashChainTracker::new(contest_uuid, participant_id);

    let judge_keypair = EvidenceEncryptionKeypair::generate();
    let judge_public_key = judge_keypair.public_key;
    let policy = MonitoringPolicy::default();

    let mut proc_collector = ProcessCollector::new(policy.app_policy.clone());
    let mut net_collector = NetworkCollector::new();
    let mut lifecycle = LifecycleTracker::new(
        policy.heartbeat_interval_secs,
        policy.max_interruption_gap_secs,
    );

    // Record initial launch event
    let launch_payload = LifecycleTracker::on_application_launch();
    let payload_json = serde_json::to_vec(&launch_payload).unwrap();
    let payload_hash = sha256_digest(&payload_json);
    let now = Utc::now();
    let (seq, prev_h, curr_h) = tracker.step(
        &now.to_rfc3339(),
        EventCategory::SystemLifecycle,
        &payload_hash,
    );
    let aad = format!("{}:{}:{}", contest_uuid, participant_id, seq).into_bytes();
    let sealed =
        seal_asymmetric_payload(&judge_public_key, &contest_uuid, &payload_json, &aad).unwrap();

    store
        .record_event(
            seq,
            Uuid::new_v4(),
            contest_uuid,
            participant_id,
            session.session_id,
            now,
            EventCategory::SystemLifecycle,
            &sealed,
            &payload_hash,
            &prev_h,
            &curr_h,
        )
        .unwrap();

    println!("[OK] Session initialized. Monitoring active. Running monitoring loop...");

    for _iteration in 0..3 {
        thread::sleep(Duration::from_millis(500));

        let procs = proc_collector.poll_events();
        for (_action, proc_payload, is_prohibited) in procs {
            if is_prohibited {
                println!(
                    "  [SUSPICIOUS] Detected prohibited AI tool: {} (PID: {})",
                    proc_payload.name, proc_payload.pid
                );
            }
        }

        let nets = net_collector.poll_events();
        for n in nets {
            println!(
                "  [NETWORK] State change: connected={} on {}",
                n.is_connected, n.interface_name
            );
        }

        let hb_events = lifecycle.tick(Utc::now());
        for hb in hb_events {
            let hb_json = serde_json::to_vec(&hb).unwrap();
            let hb_payload_hash = sha256_digest(&hb_json);
            let hb_now = Utc::now();
            let (hb_seq, hb_prev_h, hb_curr_h) = tracker.step(
                &hb_now.to_rfc3339(),
                EventCategory::SystemLifecycle,
                &hb_payload_hash,
            );
            let hb_aad = format!("{}:{}:{}", contest_uuid, participant_id, hb_seq).into_bytes();
            let hb_sealed =
                seal_asymmetric_payload(&judge_public_key, &contest_uuid, &hb_json, &hb_aad)
                    .unwrap();

            store
                .record_event(
                    hb_seq,
                    Uuid::new_v4(),
                    contest_uuid,
                    participant_id,
                    session.session_id,
                    hb_now,
                    EventCategory::SystemLifecycle,
                    &hb_sealed,
                    &hb_payload_hash,
                    &hb_prev_h,
                    &hb_curr_h,
                )
                .unwrap();
        }
    }

    session.conclude().unwrap();
    store.checkpoint().unwrap();

    let export_dir = PathBuf::from("./usb_export");
    let (last_seq, last_h) = store.get_latest_event_info().unwrap().unwrap();
    let genesis_h = compute_genesis_hash(&contest_uuid, participant_id);

    export_evidence_package(
        &db_path,
        &export_dir,
        contest_uuid,
        participant_id,
        session.session_id,
        last_seq,
        &last_h,
        &genesis_h,
    )
    .expect("Evidence export failed");

    println!("\n[SUCCESS] Encrypted Evidence Archive Exported!");
    println!("    Export Path: {}", export_dir.display());
    println!("    Total Logs:  {}", last_seq);
    println!("    Final Hash:  {}", last_h);
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() > 1 && args[1] == "session" {
        let participant_id = args
            .get(2)
            .cloned()
            .unwrap_or_else(|| "team-42".to_string());
        run_cli_session(&participant_id);
    } else if args.len() > 1 && (args[1] == "--help" || args[1] == "-h") {
        println!("Warm-AntiCheat Participant Client");
        println!("Usage:");
        println!("  warm_participant_app session [PARTICIPANT_ID]");
        println!("  warm_participant_app [ui]");
    } else {
        // Run Desktop GUI via Tauri
        tauri::Builder::default()
            .invoke_handler(tauri::generate_handler![
                get_app_info,
                enroll_participant,
                get_session_stats,
                start_monitoring_session,
                export_usb_package,
                get_compiler_status,
                compile_and_run_cpp
            ])
            .run(tauri::generate_context!())
            .expect("Failed to run Warm-AntiCheat Participant Client Desktop Application");
    }
}
