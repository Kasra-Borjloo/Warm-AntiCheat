use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventCategory {
    Process,
    Browser,
    Network,
    SystemLifecycle,
    Security,
    ManualMarker,
    Compiler,
    Auth,
}

impl std::fmt::Display for EventCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Process => write!(f, "Process"),
            Self::Browser => write!(f, "Browser"),
            Self::Network => write!(f, "Network"),
            Self::SystemLifecycle => write!(f, "SystemLifecycle"),
            Self::Security => write!(f, "Security"),
            Self::ManualMarker => write!(f, "ManualMarker"),
            Self::Compiler => write!(f, "Compiler"),
            Self::Auth => write!(f, "Auth"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceAttachmentRef {
    pub attachment_id: Uuid,
    pub filename: String,
    pub mime_type: String,
    pub sha256_hash: String,
    pub size_bytes: u64,
    pub captured_at: DateTime<Utc>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceAttachment {
    pub attachment_id: Uuid,
    pub event_sequence: u64,
    pub filename: String,
    pub mime_type: String,
    pub encrypted_payload: Vec<u8>,
    pub sha256_hash: String,
    pub size_bytes: u64,
    pub captured_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessEventPayload {
    pub pid: u32,
    pub name: String,
    pub path: Option<String>,
    pub cmdline: Option<String>,
    pub action: ProcessAction,
    #[serde(default)]
    pub screenshot_attachment: Option<EvidenceAttachmentRef>,
    #[serde(default)]
    pub listening_ports: Vec<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessAction {
    Started,
    Terminated,
    Snapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserEventPayload {
    pub domain: String,
    pub window_title: Option<String>,
    pub browser_exe: Option<String>,
    pub is_restricted: bool,
    #[serde(default)]
    pub screenshot_attachment: Option<EvidenceAttachmentRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkEventPayload {
    pub interface_name: String,
    pub interface_type: NetworkInterfaceType,
    pub is_connected: bool,
    pub ssid: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkInterfaceType {
    WiFi,
    Ethernet,
    Loopback,
    Virtual,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LifecycleEventPayload {
    pub event_type: LifecycleEventType,
    pub details: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LifecycleEventType {
    ApplicationLaunch,
    ApplicationExit,
    SessionStart,
    SessionEnd,
    Heartbeat,
    SleepDetected,
    WakeDetected,
    ShutdownSignal,
    MonitoringInterrupted,
    MonitoringRecovered,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompilerEventPayload {
    pub source_path: String,
    pub source_sha256: String,
    pub source_snapshot: String,
    pub compiler_version: String,
    pub toolchain_hash: String,
    pub compilation_args: Vec<String>,
    pub compilation_start: DateTime<Utc>,
    pub compilation_end: DateTime<Utc>,
    pub compiler_exit_code: Option<i32>,
    pub compiler_diagnostics: String,
    pub output_executable_hash: Option<String>,
    pub execution_started: bool,
    pub execution_start: Option<DateTime<Utc>>,
    pub execution_end: Option<DateTime<Utc>>,
    pub program_exit_code: Option<i32>,
    pub resource_violations: Option<String>,
    pub execution_error: Option<String>,
    pub executable_args: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthEventPayload {
    pub action: AuthAction,
    pub username: String,
    pub account_id: Option<Uuid>,
    pub timestamp: DateTime<Utc>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthAction {
    LoginSuccess,
    LoginFailure,
    Logout,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    pub event_uuid: Uuid,
    pub contest_uuid: Uuid,
    pub participant_id: String,
    pub session_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub category: EventCategory,
    pub payload: serde_json::Value,
    pub sequence_number: u64,
    pub previous_event_hash: String,
    pub current_event_hash: String,
}

impl AuditEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contest_uuid: Uuid,
        participant_id: impl Into<String>,
        session_id: Uuid,
        category: EventCategory,
        payload: serde_json::Value,
        sequence_number: u64,
        previous_event_hash: impl Into<String>,
        current_event_hash: impl Into<String>,
    ) -> Self {
        Self {
            event_uuid: Uuid::new_v4(),
            contest_uuid,
            participant_id: participant_id.into(),
            session_id,
            timestamp: Utc::now(),
            category,
            payload,
            sequence_number,
            previous_event_hash: previous_event_hash.into(),
            current_event_hash: current_event_hash.into(),
        }
    }
}
