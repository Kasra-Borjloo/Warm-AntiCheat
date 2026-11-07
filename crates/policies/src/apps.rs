use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppPolicy {
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
                "llama-bench".to_string(),
                "llama-quantize".to_string(),
                "text-generation-webui".to_string(),
                "jan.exe".to_string(),
                "jan".to_string(),
                "gpt4all".to_string(),
                "gpt4all.exe".to_string(),
                "localai".to_string(),
                "local-ai".to_string(),
                "koboldcpp".to_string(),
                "koboldcpp.exe".to_string(),
                "vllm".to_string(),
                "transformers-cli".to_string(),
                "tabby".to_string(),
                "tabby.exe".to_string(),
            ],
        }
    }

    pub fn is_prohibited(&self, process_name: &str) -> bool {
        let clean = process_name.trim().to_lowercase();
        let clean_no_ext = clean.strip_suffix(".exe").unwrap_or(&clean);

        self.prohibited_executables.iter().any(|rule| {
            let r_clean = rule.trim().to_lowercase();
            let r_no_ext = r_clean.strip_suffix(".exe").unwrap_or(&r_clean);
            clean == r_clean || clean_no_ext == r_no_ext
        })
    }

    pub fn inspect_command_line(cmdline: &str) -> Option<(&'static str, &'static str)> {
        let lower = cmdline.to_lowercase();

        let is_interpreter = lower.contains("python")
            || lower.contains("python3")
            || lower.contains("node")
            || lower.contains("bun")
            || lower.contains("deno");

        if !is_interpreter {
            return None;
        }

        if lower.contains("llama_cpp") || lower.contains("llama-cpp-python") {
            return Some((
                "llama-cpp-python",
                "Local llama.cpp Python bindings execution",
            ));
        }

        if lower.contains("vllm.entrypoints") || lower.contains("vllm serve") {
            return Some(("vllm", "High-throughput local LLM inference server"));
        }

        if lower.contains("text-generation-webui")
            || (lower.contains("server.py") && lower.contains("--model"))
        {
            return Some((
                "text-generation-webui",
                "Text Generation WebUI model server",
            ));
        }

        if lower.contains("ollama run") || lower.contains("ollama serve") {
            return Some(("ollama", "Ollama local model execution invocation"));
        }

        if (lower.contains(".gguf") || lower.contains(".safetensors"))
            && (lower.contains("--model") || lower.contains("-m "))
        {
            return Some((
                "model-weights-loader",
                "Direct execution loading local LLM model weights",
            ));
        }

        if lower.contains("automodelforcausallm") || lower.contains("pipeline(\"text-generation") {
            return Some((
                "transformers-inference",
                "HuggingFace causal language model generation",
            ));
        }

        None
    }

    pub fn is_ai_server_endpoint(port: u16) -> Option<(&'static str, &'static str)> {
        match port {
            11434 => Some((
                "Ollama Server",
                "Ollama default local API server (port 11434)",
            )),
            1234 => Some(("LM Studio", "LM Studio local inference server (port 1234)")),
            8080 => Some((
                "llama.cpp / LocalAI",
                "llama.cpp / LocalAI default HTTP server (port 8080)",
            )),
            5000 => Some(("KoboldCpp", "KoboldCpp default server (port 5000)")),
            7860 => Some((
                "WebUI / Gradio",
                "Text Generation WebUI / Gradio default interface (port 7860)",
            )),
            8000 => Some(("vLLM", "vLLM OpenAI-compatible server (port 8000)")),
            _ => None,
        }
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
        assert!(policy.is_prohibited("koboldcpp.exe"));
        assert!(policy.is_prohibited("vllm"));
        assert!(!policy.is_prohibited("code.exe"));
        assert!(!policy.is_prohibited("rustc.exe"));
        assert!(!policy.is_prohibited("python.exe"));
    }

    #[test]
    fn test_inspect_command_line_ai_runtimes() {
        let cmd1 = "python -m llama_cpp.server --model models/mistral.gguf";
        assert!(AppPolicy::inspect_command_line(cmd1).is_some());

        let cmd2 = "python server.py --model meta-llama-3-8b --listen";
        assert!(AppPolicy::inspect_command_line(cmd2).is_some());

        let cmd3 = "python -m vllm.entrypoints.openai.api_server --model llama";
        assert!(AppPolicy::inspect_command_line(cmd3).is_some());

        let cmd4 = "python3 run_model.py -m weights.safetensors";
        assert!(AppPolicy::inspect_command_line(cmd4).is_some());
    }

    #[test]
    fn test_inspect_command_line_clean_python_scripts() {
        let cmd1 = "python solution.py";
        assert!(AppPolicy::inspect_command_line(cmd1).is_none());

        let cmd2 = "python -m pytest tests/";
        assert!(AppPolicy::inspect_command_line(cmd2).is_none());

        let cmd3 = "python3 -c \"import math; print(math.sqrt(16))\"";
        assert!(AppPolicy::inspect_command_line(cmd3).is_none());

        let cmd4 = "python grader.py --input test1.in --output test1.out";
        assert!(AppPolicy::inspect_command_line(cmd4).is_none());
    }

    #[test]
    fn test_is_ai_server_endpoint() {
        assert!(AppPolicy::is_ai_server_endpoint(11434).is_some());
        assert!(AppPolicy::is_ai_server_endpoint(1234).is_some());
        assert!(AppPolicy::is_ai_server_endpoint(8080).is_some());
        assert!(AppPolicy::is_ai_server_endpoint(7860).is_some());
        assert!(AppPolicy::is_ai_server_endpoint(80).is_none());
        assert!(AppPolicy::is_ai_server_endpoint(443).is_none());
    }
}
