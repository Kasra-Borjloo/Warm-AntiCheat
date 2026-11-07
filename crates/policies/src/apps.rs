use serde::{Deserialize, Serialize};

/// Policy rules defining prohibited process executables.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppPolicy {
    /// List of prohibited executable names (case-insensitive matching).
    pub prohibited_executables: Vec<String>,
}

impl Default for AppPolicy {
    fn default() -> Self {
        Self::default_ai_rules()
    }
}

impl AppPolicy {
    pub fn new(prohibited_executables: Vec<String>) -> Self {
        Self {
            prohibited_executables,
        }
    }

    /// Default baseline rules detecting common unauthorized local AI inference runtimes.
    pub fn default_ai_rules() -> Self {
        Self {
            prohibited_executables: vec![
                "ollama".to_string(),
                "ollama.exe".to_string(),
                "ollama_llama_server.exe".to_string(),
                "lmstudio".to_string(),
                "lmstudio.exe".to_string(),
                "lm-studio".to_string(),
                "llama-cli".to_string(),
                "llama-cli.exe".to_string(),
                "llama-server".to_string(),
                "llama-server.exe".to_string(),
                "text-generation-webui".to_string(),
                "jan.exe".to_string(),
                "jan".to_string(),
                "gpt4all".to_string(),
                "gpt4all.exe".to_string(),
                "localai".to_string(),
            ],
        }
    }

    /// Check if a process name matches any prohibited rule (case-insensitive).
    pub fn is_prohibited(&self, process_name: &str) -> bool {
        let clean = process_name.trim().to_lowercase();
        // Check exact match or match without .exe extension
        let clean_no_ext = clean.strip_suffix(".exe").unwrap_or(&clean);

        self.prohibited_executables.iter().any(|rule| {
            let r_clean = rule.trim().to_lowercase();
            let r_no_ext = r_clean.strip_suffix(".exe").unwrap_or(&r_clean);
            clean == r_clean || clean_no_ext == r_no_ext
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_policy() {
        let policy = AppPolicy::default();
        assert!(policy.is_prohibited("ollama.exe"));
        assert!(policy.is_prohibited("OLLAMA"));
        assert!(policy.is_prohibited("lmstudio"));
        assert!(policy.is_prohibited("llama-cli.exe"));
        assert!(!policy.is_prohibited("code.exe"));
        assert!(!policy.is_prohibited("rustc.exe"));
    }
}
