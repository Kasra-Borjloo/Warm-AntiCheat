#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use uuid::Uuid;
use warm_builder_core::{SignedContestManifest, SignedExportAuthToken};
use warm_compiler::{
    BundledToolchain, CompilationRequest, CompilerEngine, ExecutionRequest, ExecutionRunner,
};
use warm_core::{CompetitionSession, EnrollmentToken, ParticipationMode};
use warm_crypto::{
    compute_genesis_hash, seal_asymmetric_payload, sha256_digest, EvidenceEncryptionKeypair,
    X25519PublicKey,
};
use warm_events::{AuthAction, AuthEventPayload, CompilerEventPayload, EventCategory};
use warm_platform::{LifecycleTracker, NetworkCollector, ProcessCollector};
use warm_policies::MonitoringPolicy;
use warm_storage::{export_evidence_package, HashChainTracker, SqliteAuditStore};

static ACTIVE_SESSION: Mutex<Option<Arc<ActiveSession>>> = Mutex::new(None);
static PENDING_AUTH: Mutex<Option<(Uuid, String)>> = Mutex::new(None);
static USB_STATUS: Mutex<Option<UsbStatusResponse>> = Mutex::new(None);
static LAST_USB_NONCE: Mutex<Option<String>> = Mutex::new(None);
static EVENT_COUNT: AtomicU64 = AtomicU64::new(0);
static SESSION_RUNNING: AtomicBool = AtomicBool::new(false);
static FAILED_ATTEMPTS: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub success: bool,
    pub account_id: Uuid,
    pub username: String,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ParticipationModeResponse {
    pub mode: String,
    pub requires_login: bool,
    pub contest_id: String,
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbStatusResponse {
    pub detected: bool,
    pub authorized: bool,
    pub success: bool,
    pub export_path: String,
    pub checksum: String,
    pub message: String,
    pub timestamp: String,
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

struct ActiveSession {
    contest_id: String,
    contest_uuid: Uuid,
    participant_id: String,
    session_id: Uuid,
    judge_public_key: X25519PublicKey,
    manifest_signing_key_pub_hex: String,
    raw_manifest_json: Vec<u8>,
    manifest_signature_hex: String,
    store: SqliteAuditStore,
    tracker: Mutex<HashChainTracker>,
    db_path: PathBuf,
    authenticated_account_id: Option<Uuid>,
    concluded: AtomicBool,
    start_time: Instant,
}

impl ActiveSession {
    fn record_event(&self, category: EventCategory, payload_json: &[u8]) -> Result<u64, String> {
        let payload_hash = sha256_digest(payload_json);
        let now = Utc::now();
        let timestamp_str = now.to_rfc3339();

        let (seq, prev_h, curr_h) = {
            let mut trk = self.tracker.lock().unwrap();
            trk.step(&timestamp_str, category, &payload_hash)
        };

        let aad = format!("{}:{}:{}", self.contest_uuid, self.participant_id, seq).into_bytes();
        let sealed = seal_asymmetric_payload(
            &self.judge_public_key,
            &self.contest_uuid,
            payload_json,
            &aad,
        )
        .map_err(|e| e.to_string())?;

        self.store
            .record_event(
                seq,
                Uuid::new_v4(),
                self.contest_uuid,
                &self.participant_id,
                self.session_id,
                now,
                category,
                &sealed,
                &payload_hash,
                &prev_h,
                &curr_h,
            )
            .map_err(|e| e.to_string())?;

        EVENT_COUNT.store(seq, Ordering::SeqCst);
        Ok(seq)
    }

    fn conclude(&self) -> Result<(), String> {
        if self.concluded.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let end_payload = LifecycleTracker::on_session_end();
        let json = serde_json::to_vec(&end_payload).map_err(|e| e.to_string())?;
        let _ = self.record_event(EventCategory::SystemLifecycle, &json);
        self.store.checkpoint().map_err(|e| e.to_string())?;
        Ok(())
    }
}

fn locate_and_load_manifest() -> Option<SignedContestManifest> {
    let mut candidates = Vec::new();

    if let Ok(p) = env::var("WARM_CONTEST_MANIFEST") {
        candidates.push(PathBuf::from(p));
    }

    if let Ok(exe) = env::current_exe() {
        if let Some(parent) = exe.parent() {
            candidates.push(parent.join("contest_manifest.json"));
            candidates.push(parent.join("manifests").join("contest_manifest.json"));
            if let Some(grandparent) = parent.parent() {
                candidates.push(grandparent.join("manifests").join("contest_manifest.json"));
                candidates.push(grandparent.join("contest_manifest.json"));
            }
        }
    }

    candidates.push(PathBuf::from("./contest_manifest.json"));
    candidates.push(PathBuf::from("./manifests/contest_manifest.json"));
    candidates.push(PathBuf::from("../manifests/contest_manifest.json"));
    candidates.push(PathBuf::from("../../manifests/contest_manifest.json"));
    candidates.push(PathBuf::from("./client/windows/contest_manifest.json"));
    candidates.push(PathBuf::from("../client/windows/contest_manifest.json"));

    for path in candidates {
        if path.exists() && path.is_file() {
            if let Ok(content) = fs::read_to_string(&path) {
                if let Ok(signed) = serde_json::from_str::<SignedContestManifest>(&content) {
                    if signed.verify().is_ok() {
                        return Some(signed);
                    }
                }
            }
        }
    }
    None
}

fn get_potential_removable_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();

    #[cfg(target_os = "windows")]
    {
        for letter in b'D'..=b'Z' {
            let path = PathBuf::from(format!("{}:\\", letter as char));
            if path.exists() {
                roots.push(path);
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        for base in ["/media", "/run/media", "/mnt"] {
            let p = std::path::Path::new(base);
            if p.exists() && p.is_dir() {
                if let Ok(entries) = fs::read_dir(p) {
                    for entry in entries.flatten() {
                        let sub = entry.path();
                        if sub.is_dir() {
                            roots.push(sub.clone());
                            if let Ok(sub_entries) = fs::read_dir(&sub) {
                                for sub_entry in sub_entries.flatten() {
                                    if sub_entry.path().is_dir() {
                                        roots.push(sub_entry.path());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let volumes = std::path::Path::new("/Volumes");
        if volumes.exists() && volumes.is_dir() {
            if let Ok(entries) = fs::read_dir(volumes) {
                for entry in entries.flatten() {
                    let sub = entry.path();
                    if sub.is_dir() {
                        roots.push(sub);
                    }
                }
            }
        }
    }

    roots
}

fn package_and_export_warmac(
    session: &ActiveSession,
    target_dir: &PathBuf,
) -> Result<(PathBuf, String), String> {
    fs::create_dir_all(target_dir).map_err(|e| e.to_string())?;

    let mut attachments = Vec::new();
    let screenshots_dir = PathBuf::from("./session_data/screenshots");
    if screenshots_dir.exists() {
        if let Ok(entries) = fs::read_dir(&screenshots_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Ok(content) = fs::read(&path) {
                        let filename = path
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_string();
                        attachments.push((filename, content));
                    }
                }
            }
        }
    }

    let warmac_path = target_dir.join(format!(
        "{}_{}.warmac",
        session.contest_id, session.participant_id
    ));
    warm_storage::create_warmac_package(
        &warmac_path,
        &session.raw_manifest_json,
        &session.manifest_signature_hex,
        &session.manifest_signing_key_pub_hex,
        &session.judge_public_key,
        &session.store,
        session.contest_uuid,
        &session.participant_id,
        session.session_id,
        session.authenticated_account_id,
        &attachments,
    )
    .map_err(|e| e.to_string())?;

    warm_storage::inspect_warmac_file(&warmac_path).map_err(|e| e.to_string())?;

    let warmac_bytes = fs::read(&warmac_path).map_err(|e| e.to_string())?;
    let checksum = warm_crypto::sha256_digest(&warmac_bytes);

    let (last_seq, last_h) = session
        .store
        .get_latest_event_info()
        .unwrap_or(None)
        .unwrap_or((0, String::new()));
    let genesis_h = compute_genesis_hash(&session.contest_uuid, &session.participant_id);
    let _ = export_evidence_package(
        &session.db_path,
        target_dir,
        session.contest_uuid,
        &session.participant_id,
        session.session_id,
        last_seq,
        &last_h,
        &genesis_h,
    );

    Ok((warmac_path, checksum))
}

fn start_collector_loop(session: Arc<ActiveSession>, policy: MonitoringPolicy) {
    thread::spawn(move || {
        let mut proc_collector = ProcessCollector::new(policy.app_policy.clone());
        let mut net_collector = NetworkCollector::new();
        let mut lifecycle = LifecycleTracker::new(
            policy.heartbeat_interval_secs,
            policy.max_interruption_gap_secs,
        );

        while SESSION_RUNNING.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(1500));
            if !SESSION_RUNNING.load(Ordering::SeqCst) {
                break;
            }

            let procs = proc_collector.poll_events();
            for (_action, mut proc_payload, is_prohibited) in procs {
                let is_suspicious = is_prohibited
                    || proc_payload
                        .cmdline
                        .as_deref()
                        .and_then(warm_policies::AppPolicy::inspect_command_line)
                        .is_some();

                if is_suspicious {
                    if let Some(bmp_bytes) = warm_platform::capture_screenshot() {
                        let att_id = Uuid::new_v4();
                        let filename =
                            format!("{}_{}.bmp", att_id, Utc::now().format("%Y%m%d_%H%M%S"));
                        let sha = warm_crypto::sha256_digest(&bmp_bytes);
                        let size = bmp_bytes.len() as u64;

                        let screenshots_dir = PathBuf::from("./session_data/screenshots");
                        if fs::create_dir_all(&screenshots_dir).is_ok() {
                            let _ = fs::write(screenshots_dir.join(&filename), &bmp_bytes);
                            proc_payload.screenshot_attachment =
                                Some(warm_events::EvidenceAttachmentRef {
                                    attachment_id: att_id,
                                    filename,
                                    mime_type: "image/bmp".to_string(),
                                    sha256_hash: sha,
                                    size_bytes: size,
                                    captured_at: Utc::now(),
                                    reason: format!(
                                        "Suspicious activity detected: {}",
                                        proc_payload.name
                                    ),
                                });
                        }
                    }
                }

                if let Ok(json) = serde_json::to_vec(&proc_payload) {
                    let _ = session.record_event(EventCategory::Process, &json);
                }
            }

            let nets = net_collector.poll_events();
            for n in nets {
                if let Ok(json) = serde_json::to_vec(&n) {
                    let _ = session.record_event(EventCategory::Network, &json);
                }
            }

            let hb_events = lifecycle.tick(Utc::now());
            for hb in hb_events {
                if let Ok(json) = serde_json::to_vec(&hb) {
                    let _ = session.record_event(EventCategory::SystemLifecycle, &json);
                }
            }
        }
    });
}

fn start_usb_watcher() {
    thread::spawn(|| {
        while SESSION_RUNNING.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(1500));
            if !SESSION_RUNNING.load(Ordering::SeqCst) {
                break;
            }

            let maybe_session = {
                let guard = ACTIVE_SESSION.lock().unwrap();
                guard.as_ref().cloned()
            };

            let session = match maybe_session {
                Some(s) => s,
                None => continue,
            };

            if session.manifest_signing_key_pub_hex.is_empty() {
                continue;
            }

            let roots = get_potential_removable_roots();
            for root in roots {
                let token_candidates = [
                    root.join("warm_export_auth.token"),
                    root.join("usb_token").join("warm_export_auth.token"),
                ];

                for token_path in &token_candidates {
                    if !token_path.exists() {
                        continue;
                    }

                    let content = match fs::read_to_string(token_path) {
                        Ok(c) => c,
                        Err(_) => continue,
                    };

                    let signed_token = match serde_json::from_str::<SignedExportAuthToken>(&content)
                    {
                        Ok(t) => t,
                        Err(_) => continue,
                    };

                    if signed_token
                        .verify(&session.manifest_signing_key_pub_hex)
                        .is_err()
                    {
                        continue;
                    }

                    if signed_token.token.contest_id != session.contest_id
                        || signed_token.token.purpose != "CONTEST_LOG_EXPORT_AUTHORIZATION"
                    {
                        continue;
                    }

                    {
                        let last_nonce = LAST_USB_NONCE.lock().unwrap();
                        if last_nonce.as_deref() == Some(&signed_token.token.nonce) {
                            continue;
                        }
                    }

                    let folder_name = format!(
                        "{}_{}_{}",
                        session.contest_id,
                        session.participant_id,
                        Utc::now().format("%Y%m%d_%H%M%S")
                    );
                    let target_dir = root.join("warm_logs").join(folder_name);

                    let _ = session.conclude();

                    match package_and_export_warmac(&session, &target_dir) {
                        Ok((warmac_path, checksum)) => {
                            *LAST_USB_NONCE.lock().unwrap() =
                                Some(signed_token.token.nonce.clone());
                            *USB_STATUS.lock().unwrap() = Some(UsbStatusResponse {
                                detected: true,
                                authorized: true,
                                success: true,
                                export_path: warmac_path.display().to_string(),
                                checksum,
                                message: format!(
                                    "Authorized USB export verified: {}",
                                    warmac_path.display()
                                ),
                                timestamp: Utc::now().to_rfc3339(),
                            });
                            SESSION_RUNNING.store(false, Ordering::SeqCst);
                            break;
                        }
                        Err(_) => continue,
                    }
                }
            }
        }
    });
}

#[tauri::command]
fn get_app_info() -> ParticipantAppInfo {
    if let Some(signed) = locate_and_load_manifest() {
        ParticipantAppInfo {
            version: env!("CARGO_PKG_VERSION").to_string(),
            contest_title: signed.manifest.contest.title,
            contest_id: signed.manifest.contest.id,
        }
    } else {
        ParticipantAppInfo {
            version: env!("CARGO_PKG_VERSION").to_string(),
            contest_title: "Warm-AntiCheat Competition".to_string(),
            contest_id: "warm-contest".to_string(),
        }
    }
}

#[tauri::command]
fn enroll_participant(token_str: String) -> EnrollmentResult {
    let contest_id = locate_and_load_manifest()
        .map(|m| m.manifest.contest.id)
        .unwrap_or_else(|| "warm-contest".to_string());

    match EnrollmentToken::new(&contest_id, "participant", token_str, "sig_valid") {
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
    let (running, uptime) = {
        let guard = ACTIVE_SESSION.lock().unwrap();
        if let Some(s) = guard.as_ref() {
            let is_running =
                SESSION_RUNNING.load(Ordering::SeqCst) && !s.concluded.load(Ordering::SeqCst);
            let up = s.start_time.elapsed().as_secs();
            (is_running, up)
        } else {
            (false, 0)
        }
    };
    SessionStats {
        running,
        event_count: EVENT_COUNT.load(Ordering::SeqCst),
        uptime_secs: uptime,
    }
}

#[tauri::command]
fn start_monitoring_session(participant_id: String) -> Result<String, String> {
    if SESSION_RUNNING.load(Ordering::SeqCst) {
        return Ok("Session already active".to_string());
    }

    let manifest_opt = locate_and_load_manifest();
    let (
        contest_id,
        contest_uuid,
        judge_pk,
        signing_pk_hex,
        policy,
        raw_manifest_json,
        manifest_sig_hex,
    ) = match manifest_opt {
        Some(signed) => {
            let pk_bytes = hex::decode(&signed.manifest.judge_public_key_hex)
                .map_err(|e| format!("Invalid judge public key hex: {e}"))?;
            if pk_bytes.len() != 32 {
                return Err("Judge public key must be 32 bytes".to_string());
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&pk_bytes);
            let raw_m = serde_json::to_vec(&signed.manifest).unwrap_or_default();
            (
                signed.manifest.contest.id,
                signed.manifest.contest.uuid,
                X25519PublicKey::from(arr),
                signed.manifest.manifest_signing_key_pub_hex,
                signed.manifest.policy,
                raw_m,
                signed.signature_hex,
            )
        }
        None => {
            let kp = EvidenceEncryptionKeypair::generate();
            let c_id = "warm-contest".to_string();
            let c_uuid = Uuid::new_v4();
            let raw_m = serde_json::to_vec(&serde_json::json!({
                "id": c_id,
                "uuid": c_uuid,
                "title": "Warm-AntiCheat Competition",
                "organization": "Default Organization"
            }))
            .unwrap_or_default();
            (
                c_id,
                c_uuid,
                kp.public_key,
                String::new(),
                MonitoringPolicy::default(),
                raw_m,
                String::new(),
            )
        }
    };

    let auth_info = PENDING_AUTH.lock().unwrap().take();
    let (authenticated_account_id, real_participant_id) = match auth_info {
        Some((acc_id, uname)) => (Some(acc_id), uname),
        None => (None, participant_id),
    };

    let session_dir = PathBuf::from("./session_data");
    fs::create_dir_all(&session_dir).map_err(|e| e.to_string())?;
    let db_path = session_dir.join("audit.sqlite");

    let store = SqliteAuditStore::open(&db_path).map_err(|e| e.to_string())?;

    let recovery_info = store.get_session_recovery_info().unwrap_or(None);
    let (tracker, session_id, is_resumed) = match recovery_info {
        Some(info) if info.last_sequence > 0 && info.participant_id == real_participant_id => (
            HashChainTracker::resume(
                contest_uuid,
                &real_participant_id,
                info.last_sequence,
                &info.last_hash,
            ),
            info.session_id,
            true,
        ),
        _ => (
            HashChainTracker::new(contest_uuid, &real_participant_id),
            Uuid::new_v4(),
            false,
        ),
    };

    let session = Arc::new(ActiveSession {
        contest_id,
        contest_uuid,
        participant_id: real_participant_id.clone(),
        session_id,
        judge_public_key: judge_pk,
        manifest_signing_key_pub_hex: signing_pk_hex,
        raw_manifest_json,
        manifest_signature_hex: manifest_sig_hex,
        store,
        tracker: Mutex::new(tracker),
        db_path,
        authenticated_account_id,
        concluded: AtomicBool::new(false),
        start_time: Instant::now(),
    });

    if is_resumed {
        let interrupted_payload = LifecycleTracker::on_monitoring_interrupted(
            "Monitoring interrupted due to client restart or process suspension",
        );
        let int_json = serde_json::to_vec(&interrupted_payload).map_err(|e| e.to_string())?;
        session.record_event(EventCategory::SystemLifecycle, &int_json)?;

        let recovered_payload = LifecycleTracker::on_monitoring_recovered(
            "Monitoring resumed from existing tamper-evident SQLite storage",
        );
        let rec_json = serde_json::to_vec(&recovered_payload).map_err(|e| e.to_string())?;
        session.record_event(EventCategory::SystemLifecycle, &rec_json)?;
    } else {
        let launch_payload = LifecycleTracker::on_application_launch();
        let launch_json = serde_json::to_vec(&launch_payload).map_err(|e| e.to_string())?;
        session.record_event(EventCategory::SystemLifecycle, &launch_json)?;

        let start_payload = LifecycleTracker::on_session_start();
        let start_json = serde_json::to_vec(&start_payload).map_err(|e| e.to_string())?;
        session.record_event(EventCategory::SystemLifecycle, &start_json)?;

        if let Some(acc_id) = authenticated_account_id {
            let auth_payload = AuthEventPayload {
                action: AuthAction::LoginSuccess,
                username: real_participant_id.clone(),
                account_id: Some(acc_id),
                timestamp: Utc::now(),
                note: Some("Argon2id authentication confirmed".to_string()),
            };
            let auth_json = serde_json::to_vec(&auth_payload).map_err(|e| e.to_string())?;
            session.record_event(EventCategory::Auth, &auth_json)?;
        }
    }

    *ACTIVE_SESSION.lock().unwrap() = Some(session.clone());
    SESSION_RUNNING.store(true, Ordering::SeqCst);

    start_collector_loop(session, policy);
    start_usb_watcher();

    Ok(format!(
        "Monitoring session started for participant {real_participant_id}"
    ))
}

#[tauri::command]
fn conclude_session() -> Result<String, String> {
    let guard = ACTIVE_SESSION.lock().unwrap();
    if let Some(session) = guard.as_ref() {
        session.conclude()?;
        SESSION_RUNNING.store(false, Ordering::SeqCst);
        Ok("Competition session concluded successfully.".to_string())
    } else {
        SESSION_RUNNING.store(false, Ordering::SeqCst);
        Ok("Session concluded.".to_string())
    }
}

#[tauri::command]
fn validate_log_name(name: String) -> Result<String, String> {
    warm_core::sanitize_log_name(&name).map_err(|e| e.to_string())
}

#[tauri::command]
fn get_participation_mode() -> ParticipationModeResponse {
    if let Some(signed) = locate_and_load_manifest() {
        let is_gen = signed.manifest.account_mode.mode == ParticipationMode::GeneratedAccounts;
        ParticipationModeResponse {
            mode: if is_gen {
                "generated_accounts".to_string()
            } else {
                "no_accounts".to_string()
            },
            requires_login: is_gen,
            contest_id: signed.manifest.contest.id,
        }
    } else {
        ParticipationModeResponse {
            mode: "no_accounts".to_string(),
            requires_login: false,
            contest_id: "warm-contest".to_string(),
        }
    }
}

#[tauri::command]
fn login_participant_account(
    contest_id: String,
    username: String,
    password: String,
) -> Result<LoginResponse, String> {
    let failed = FAILED_ATTEMPTS.load(Ordering::SeqCst);
    if failed >= 5 {
        thread::sleep(Duration::from_millis(500));
    }

    let manifest = locate_and_load_manifest()
        .ok_or_else(|| "Contest configuration manifest not found or invalid.".to_string())?;

    if !contest_id.is_empty() && contest_id != manifest.manifest.contest.id {
        FAILED_ATTEMPTS.fetch_add(1, Ordering::SeqCst);
        return Err("Invalid credentials".to_string());
    }

    if manifest.manifest.account_mode.mode != ParticipationMode::GeneratedAccounts {
        return Err("Contest is not configured for account authentication".to_string());
    }

    let target = manifest
        .manifest
        .account_mode
        .verifiers
        .iter()
        .find(|v| v.username.eq_ignore_ascii_case(&username));

    match target {
        Some(v) => {
            if warm_crypto::verify_password(&password, &v.password_hash) {
                FAILED_ATTEMPTS.store(0, Ordering::SeqCst);
                *PENDING_AUTH.lock().unwrap() = Some((v.account_id, v.username.clone()));
                Ok(LoginResponse {
                    success: true,
                    account_id: v.account_id,
                    username: v.username.clone(),
                    message: "Authentication successful".to_string(),
                })
            } else {
                FAILED_ATTEMPTS.fetch_add(1, Ordering::SeqCst);
                Err("Invalid credentials".to_string())
            }
        }
        None => {
            let _ = warm_crypto::verify_password(
                &password,
                "$argon2id$v=19$m=19456,t=2,p=1$M29ja19zYWx0XzEyMzQ1$MockHashComparisonForConstantTimeDummyPass12345",
            );
            FAILED_ATTEMPTS.fetch_add(1, Ordering::SeqCst);
            Err("Invalid credentials".to_string())
        }
    }
}

#[tauri::command]
fn export_contest_log(
    dest_folder: Option<String>,
    declared_log_name: Option<String>,
) -> ExportResult {
    let session_guard = ACTIVE_SESSION.lock().unwrap();
    let session = match session_guard.as_ref() {
        Some(s) => s,
        None => {
            return ExportResult {
                success: false,
                export_path: String::new(),
                checksum: String::new(),
                message: "No active or recorded session found to export.".to_string(),
            };
        }
    };

    if let Err(e) = session.conclude() {
        return ExportResult {
            success: false,
            export_path: String::new(),
            checksum: String::new(),
            message: format!("Failed to conclude session: {e}"),
        };
    }

    let out_dir = match dest_folder {
        Some(d) if !d.trim().is_empty() => PathBuf::from(d.trim()),
        _ => PathBuf::from("./export"),
    };

    let target_dir = if session.authenticated_account_id.is_some() {
        out_dir.join(format!("{}_{}", session.contest_id, session.participant_id))
    } else if let Some(ref name) = declared_log_name {
        match warm_core::sanitize_log_name(name) {
            Ok(sanitized) => out_dir.join(&sanitized),
            Err(e) => {
                return ExportResult {
                    success: false,
                    export_path: String::new(),
                    checksum: String::new(),
                    message: format!("Invalid log name: {e}"),
                };
            }
        }
    } else {
        out_dir
    };

    if let Err(e) = fs::create_dir_all(&target_dir) {
        return ExportResult {
            success: false,
            export_path: String::new(),
            checksum: String::new(),
            message: format!("Failed to create export directory: {e}"),
        };
    }

    match package_and_export_warmac(session, &target_dir) {
        Ok((warmac_path, checksum)) => ExportResult {
            success: true,
            export_path: warmac_path.display().to_string(),
            checksum,
            message: "Encrypted evidence archive (.warmac) exported and verified successfully."
                .to_string(),
        },
        Err(e) => ExportResult {
            success: false,
            export_path: String::new(),
            checksum: String::new(),
            message: format!("Failed to export evidence archive: {e}"),
        },
    }
}

#[tauri::command]
fn export_usb_package(dest_folder: Option<String>) -> ExportResult {
    export_contest_log(dest_folder, None)
}

#[tauri::command]
fn pick_export_folder() -> Option<String> {
    rfd::FileDialog::new()
        .set_title("Select Export Destination Directory")
        .pick_folder()
        .map(|p| p.display().to_string())
}

#[tauri::command]
fn get_usb_status() -> Option<UsbStatusResponse> {
    USB_STATUS.lock().unwrap().clone()
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

    let comp_start_utc = Utc::now();
    let comp_req = CompilationRequest {
        source_path: PathBuf::from("solution.cpp"),
        source_code: Some(source_code.clone()),
        output_dir: None,
        optimization_level: Some("-O2".to_string()),
        standard: Some("-std=c++23".to_string()),
        extra_args: vec!["-pipe".to_string()],
    };

    let comp_res = engine.compile(comp_req).map_err(|e| e.to_string())?;
    let comp_end_utc = Utc::now();

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

    let payload = CompilerEventPayload {
        source_path: "solution.cpp".to_string(),
        source_sha256: comp_res.source_sha256.clone(),
        source_snapshot: source_code,
        compiler_version: engine.toolchain().version.clone(),
        toolchain_hash: engine.toolchain().sha256_hash.clone(),
        compilation_args: vec![
            "-std=c++23".to_string(),
            "-O2".to_string(),
            "-pipe".to_string(),
        ],
        compilation_start: comp_start_utc,
        compilation_end: comp_end_utc,
        compiler_exit_code: if comp_res.success { Some(0) } else { Some(1) },
        compiler_diagnostics: comp_res.diagnostics.clone(),
        output_executable_hash: comp_res.output_binary_hash.clone(),
        execution_started: exec_started,
        execution_start: Some(comp_end_utc),
        execution_end: Some(Utc::now()),
        program_exit_code: exit_code,
        resource_violations: violation.clone(),
        execution_error: None,
        executable_args: Vec::new(),
    };

    if let Ok(json) = serde_json::to_vec(&payload) {
        let guard = ACTIVE_SESSION.lock().unwrap();
        if let Some(session) = guard.as_ref() {
            let _ = session.record_event(EventCategory::Compiler, &json);
        }
    }

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

    let mut session = CompetitionSession::new("warm-contest", participant_id).unwrap();
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
        tauri::Builder::default()
            .invoke_handler(tauri::generate_handler![
                get_app_info,
                enroll_participant,
                get_session_stats,
                start_monitoring_session,
                conclude_session,
                export_usb_package,
                export_contest_log,
                validate_log_name,
                login_participant_account,
                get_participation_mode,
                get_compiler_status,
                compile_and_run_cpp,
                pick_export_folder,
                get_usb_status
            ])
            .run(tauri::generate_context!())
            .expect("Failed to run Warm-AntiCheat Participant Client Desktop Application");
    }
}
