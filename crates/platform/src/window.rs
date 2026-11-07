use std::collections::HashMap;
use std::time::{Duration, Instant};
use warm_events::BrowserEventPayload;
use warm_policies::BrowserPolicy;

pub struct WindowObserver {
    policy: BrowserPolicy,
    reported_windows: HashMap<String, Instant>,
}

impl WindowObserver {
    pub fn new(policy: BrowserPolicy) -> Self {
        Self {
            policy,
            reported_windows: HashMap::new(),
        }
    }

    pub fn poll_events(&mut self) -> Vec<BrowserEventPayload> {
        let now = Instant::now();
        self.reported_windows
            .retain(|_, last_seen| now.duration_since(*last_seen) < Duration::from_secs(900));

        let mut events = Vec::new();
        let windows = Self::enumerate_all_windows();

        for (pid, title) in windows {
            if let Some((domain, is_restricted, is_ai_suspect)) = self.classify_window(&title) {
                let key = format!("{}:{}", domain, pid);
                let should_report = match self.reported_windows.get(&key) {
                    Some(last_reported) => {
                        now.duration_since(*last_reported) > Duration::from_secs(120)
                    }
                    None => true,
                };

                if should_report {
                    self.reported_windows.insert(key, now);
                    events.push(BrowserEventPayload {
                        domain,
                        window_title: Some(title),
                        browser_exe: None,
                        is_restricted,
                        is_ai_suspect,
                        contest_relative_time: None,
                        screenshot_attachment: None,
                    });
                }
            }
        }

        events
    }

    pub fn simulate_event(
        &mut self,
        domain: &str,
        title: &str,
        browser: &str,
        is_restricted: bool,
    ) -> BrowserEventPayload {
        BrowserEventPayload {
            domain: domain.to_string(),
            window_title: Some(title.to_string()),
            browser_exe: Some(browser.to_string()),
            is_restricted,
            is_ai_suspect: is_restricted,
            contest_relative_time: None,
            screenshot_attachment: None,
        }
    }

    fn classify_window(&self, title: &str) -> Option<(String, bool, bool)> {
        let lower = title.to_lowercase();
        if lower.contains("warm-anticheat")
            || lower.contains("warm anticheat")
            || lower.contains("warm contest")
            || lower.contains("warm participant")
            || lower.contains("warm judge")
        {
            return None;
        }

        for domain in &self.policy.restricted_domains {
            let dom_lower = domain.to_lowercase();
            let dom_clean = dom_lower.strip_prefix("www.").unwrap_or(&dom_lower);
            if lower.contains(dom_clean) {
                return Some((domain.clone(), true, false));
            }
        }

        let ai_signatures = [
            ("chatgpt", "chatgpt.com"),
            ("openai", "chatgpt.com"),
            ("claude", "claude.ai"),
            ("anthropic", "claude.ai"),
            ("copilot", "copilot.microsoft.com"),
            ("gemini", "gemini.google.com"),
            ("perplexity", "perplexity.ai"),
            ("deepseek", "deepseek.com"),
            ("poe.com", "poe.com"),
            ("character.ai", "character.ai"),
            ("cai", "character.ai"),
            ("huggingface", "huggingface.co"),
            ("civitai", "civitai.com"),
            ("ollama", "ollama.local"),
            ("lm studio", "lmstudio.local"),
            ("jan ai", "jan.local"),
            ("koboldcpp", "koboldcpp.local"),
            ("text generation webui", "oobabooga.local"),
            ("vllm", "vllm.local"),
            ("jupyter", "jupyter.local"),
            ("mistral", "mistral.ai"),
            ("qwen", "qwen.ai"),
            ("cohere", "cohere.com"),
            ("together.ai", "together.ai"),
            ("groq", "groq.com"),
            ("replicate", "replicate.com"),
        ];

        for (pattern, domain) in ai_signatures {
            if lower.contains(pattern) {
                return Some((domain.to_string(), true, true));
            }
        }

        let is_chat_app = lower.ends_with("- discord")
            || lower.ends_with("— discord")
            || lower.contains("discord.com")
            || lower.contains("slack.com")
            || lower.ends_with("- slack")
            || lower.ends_with("- teams");

        let has_ai_heuristic = !is_chat_app
            && (lower.contains(".ai/")
                || lower.contains(".ai ")
                || lower.ends_with(".ai")
                || lower.contains(" ai ")
                || lower.contains("gpt-")
                || lower.contains(" gpt")
                || lower.contains("ai assistant")
                || lower.contains("ai chat")
                || lower.contains("chat ai")
                || lower.contains("ai model")
                || lower.contains("large language model")
                || lower.contains("generative ai"));

        let is_browser = lower.contains("chrome")
            || lower.contains("edge")
            || lower.contains("firefox")
            || lower.contains("brave")
            || lower.contains("opera")
            || lower.contains("arc")
            || lower.contains("vivaldi")
            || lower.contains("safari")
            || lower.contains("browser")
            || lower.contains(" - ")
            || lower.contains(" — ");

        if is_browser {
            let extracted = warm_policies::extract_clean_domain(title);
            let domain = if extracted.is_empty() {
                title.to_string()
            } else {
                extracted
            };
            return Some((domain, has_ai_heuristic, has_ai_heuristic));
        }

        if has_ai_heuristic {
            return Some((title.to_string(), true, true));
        }

        None
    }

    #[cfg(target_os = "windows")]
    fn enumerate_all_windows() -> Vec<(u32, String)> {
        use windows_sys::Win32::Foundation::{BOOL, HWND, LPARAM};
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            EnumWindows, GetWindowTextLengthW, GetWindowTextW, GetWindowThreadProcessId,
            IsWindowVisible,
        };

        unsafe extern "system" fn enum_callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
            if IsWindowVisible(hwnd) == 0 {
                return 1;
            }

            let len = GetWindowTextLengthW(hwnd);
            if len <= 0 || len > 2048 {
                return 1;
            }

            let mut buf = vec![0u16; (len + 1) as usize];
            let read = GetWindowTextW(hwnd, buf.as_mut_ptr(), len + 1);
            if read > 0 {
                let title = String::from_utf16_lossy(&buf[..read as usize]);
                let trimmed = title.trim();
                if !trimmed.is_empty() {
                    let mut pid = 0u32;
                    GetWindowThreadProcessId(hwnd, &mut pid);
                    let list = &mut *(lparam as *mut Vec<(u32, String)>);
                    list.push((pid, trimmed.to_string()));
                }
            }

            1
        }

        let mut list: Vec<(u32, String)> = Vec::new();
        unsafe {
            EnumWindows(
                Some(enum_callback),
                &mut list as *mut Vec<(u32, String)> as LPARAM,
            );
        }
        list
    }

    #[cfg(not(target_os = "windows"))]
    fn enumerate_all_windows() -> Vec<(u32, String)> {
        Vec::new()
    }
}
