use serde::{Deserialize, Serialize};

/// Policy rules defining restricted domain targets during active competition sessions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserPolicy {
    /// List of restricted domain hostnames.
    pub restricted_domains: Vec<String>,
}

impl Default for BrowserPolicy {
    fn default() -> Self {
        Self::default_restricted_domains()
    }
}

impl BrowserPolicy {
    pub fn new(restricted_domains: Vec<String>) -> Self {
        Self { restricted_domains }
    }

    /// Default baseline rules detecting popular AI chat and LLM interfaces.
    pub fn default_restricted_domains() -> Self {
        Self {
            restricted_domains: vec![
                "chatgpt.com".to_string(),
                "openai.com".to_string(),
                "claude.ai".to_string(),
                "anthropic.com".to_string(),
                "gemini.google.com".to_string(),
                "copilot.microsoft.com".to_string(),
                "perplexity.ai".to_string(),
                "poe.com".to_string(),
                "deepseek.com".to_string(),
                "mistral.ai".to_string(),
                "huggingface.co".to_string(),
            ],
        }
    }

    /// Check if target domain or URL violates restricted domain policy.
    pub fn is_restricted(&self, target: &str) -> bool {
        let domain = extract_clean_domain(target);
        if domain.is_empty() {
            return false;
        }

        self.restricted_domains.iter().any(|rule| {
            let r = rule.trim().to_lowercase();
            domain == r || domain.ends_with(&format!(".{r}"))
        })
    }
}

/// Normalize URLs and target strings to bare lowercase domain names.
pub fn extract_clean_domain(target: &str) -> String {
    let mut clean = target.trim().to_lowercase();

    // Strip http:// or https:// prefix
    if let Some(pos) = clean.find("://") {
        clean = clean[pos + 3..].to_string();
    }

    // Strip path and query parameters
    if let Some(pos) = clean.find('/') {
        clean = clean[..pos].to_string();
    }

    // Strip port numbers
    if let Some(pos) = clean.find(':') {
        clean = clean[..pos].to_string();
    }

    clean
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_clean_domain() {
        assert_eq!(
            extract_clean_domain("https://chatgpt.com/c/1234"),
            "chatgpt.com"
        );
        assert_eq!(
            extract_clean_domain("http://sub.gemini.google.com:8080/"),
            "sub.gemini.google.com"
        );
        assert_eq!(extract_clean_domain("claude.ai"), "claude.ai");
    }

    #[test]
    fn test_browser_policy_matching() {
        let policy = BrowserPolicy::default();
        assert!(policy.is_restricted("chatgpt.com"));
        assert!(policy.is_restricted("https://chatgpt.com/chat"));
        assert!(policy.is_restricted("api.openai.com"));
        assert!(policy.is_restricted("https://gemini.google.com"));
        assert!(policy.is_restricted("claude.ai"));
        assert!(!policy.is_restricted("https://doc.rust-lang.org"));
        assert!(!policy.is_restricted("https://google.com"));
    }
}
