use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::WarmError;

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParticipationMode {
    #[default]
    NoAccounts,
    GeneratedAccounts,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountVerifier {
    pub account_id: Uuid,
    pub username: String,
    pub password_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountRecord {
    pub account_id: Uuid,
    pub username: String,
    pub plaintext_password: String,
    pub contest_id: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountModeConfig {
    pub mode: ParticipationMode,
    pub account_count: usize,
    pub verifiers: Vec<AccountVerifier>,
}

impl Default for AccountModeConfig {
    fn default() -> Self {
        Self {
            mode: ParticipationMode::NoAccounts,
            account_count: 0,
            verifiers: Vec::new(),
        }
    }
}

pub fn sanitize_log_name(raw: &str) -> Result<String, WarmError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(WarmError::Validation(
            "Log name cannot be empty".to_string(),
        ));
    }
    if trimmed.len() > 64 {
        return Err(WarmError::Validation(
            "Log name cannot exceed 64 characters".to_string(),
        ));
    }

    if trimmed.contains("..") || trimmed.contains('/') || trimmed.contains('\\') {
        return Err(WarmError::Validation(
            "Log name cannot contain path separators ('/', '\\') or '..' sequences".to_string(),
        ));
    }

    let is_safe = trimmed
        .chars()
        .all(|c| c.is_alphanumeric() || c == ' ' || c == '-' || c == '_' || c == '.');

    if !is_safe {
        return Err(WarmError::Validation(
            "Log name contains prohibited special characters. Only alphanumeric, spaces, hyphens, and underscores are allowed.".to_string(),
        ));
    }

    Ok(trimmed.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportedLogMetadata {
    pub contest_id: String,
    pub session_id: Uuid,
    pub declared_log_name: Option<String>,
    pub authenticated_account_id: Option<Uuid>,
    pub participation_mode: ParticipationMode,
    pub exported_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_log_name_valid() {
        assert_eq!(
            sanitize_log_name("Kasra_Solution-1").unwrap(),
            "Kasra_Solution-1"
        );
        assert_eq!(sanitize_log_name("  Team 42 Log  ").unwrap(), "Team 42 Log");
        assert_eq!(sanitize_log_name("Participant.A").unwrap(), "Participant.A");
    }

    #[test]
    fn test_sanitize_log_name_path_traversal() {
        assert!(sanitize_log_name("../etc/passwd").is_err());
        assert!(sanitize_log_name("..\\windows\\system32").is_err());
        assert!(sanitize_log_name("foo/bar").is_err());
        assert!(sanitize_log_name("foo\\bar").is_err());
    }

    #[test]
    fn test_sanitize_log_name_special_characters_and_length() {
        assert!(sanitize_log_name("").is_err());
        assert!(sanitize_log_name("   ").is_err());
        assert!(sanitize_log_name("bad$name!").is_err());
        assert!(sanitize_log_name("<script>").is_err());
        assert!(sanitize_log_name(&"A".repeat(65)).is_err());
    }

    #[test]
    fn test_account_mode_defaults() {
        let config = AccountModeConfig::default();
        assert_eq!(config.mode, ParticipationMode::NoAccounts);
        assert_eq!(config.account_count, 0);
        assert!(config.verifiers.is_empty());
    }
}
