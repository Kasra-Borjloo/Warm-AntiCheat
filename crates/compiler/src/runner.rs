use crate::error::{CompilerError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use warm_crypto::sha256_digest;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionRequest {
    pub binary_path: PathBuf,
    pub toolchain_bin_dir: Option<PathBuf>,
    pub stdin_input: Option<String>,
    pub timeout_ms: u64,
    pub args: Vec<String>,
}

impl Default for ExecutionRequest {
    fn default() -> Self {
        Self {
            binary_path: PathBuf::new(),
            toolchain_bin_dir: None,
            stdin_input: None,
            timeout_ms: 5000,
            args: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionResult {
    pub started: bool,
    pub executable_path: PathBuf,
    pub executable_hash: String,
    pub command_line_args: Vec<String>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub duration_ms: u128,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub resource_violation: Option<String>,
    pub error_message: Option<String>,
}

pub struct ExecutionRunner;

impl ExecutionRunner {
    pub fn execute(req: ExecutionRequest) -> Result<ExecutionResult> {
        let start_time = Utc::now();
        let timer = Instant::now();

        if !req.binary_path.exists() {
            return Err(CompilerError::Execution(format!(
                "Executable not found at {}",
                req.binary_path.display()
            )));
        }

        let bin_bytes = fs::read(&req.binary_path).map_err(CompilerError::Io)?;
        let executable_hash = sha256_digest(&bin_bytes);

        let mut cmd = Command::new(&req.binary_path);
        #[cfg(target_os = "windows")]
        cmd.creation_flags(0x08000000);
        cmd.args(&req.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        if let Some(ref bin_dir) = req.toolchain_bin_dir {
            #[cfg(target_os = "windows")]
            cmd.env(
                "PATH",
                format!("{};C:\\Windows\\System32", bin_dir.display()),
            );
            #[cfg(not(target_os = "windows"))]
            cmd.env("PATH", format!("{}:/usr/lib:/lib", bin_dir.display()));
        }

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                let end_time = Utc::now();
                return Ok(ExecutionResult {
                    started: false,
                    executable_path: req.binary_path,
                    executable_hash,
                    command_line_args: req.args,
                    start_time,
                    end_time,
                    duration_ms: timer.elapsed().as_millis(),
                    exit_code: None,
                    stdout: String::new(),
                    stderr: String::new(),
                    timed_out: false,
                    resource_violation: None,
                    error_message: Some(format!("Failed to spawn child process: {e}")),
                });
            }
        };

        if let Some(ref input) = req.stdin_input {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(input.as_bytes());
                let _ = stdin.flush();
            }
        } else {
            drop(child.stdin.take());
        }

        let mut stdout_handle = child.stdout.take();
        let mut stderr_handle = child.stderr.take();

        let stdout_thread = thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(ref mut h) = stdout_handle {
                let _ = h.read_to_end(&mut buf);
            }
            buf
        });

        let stderr_thread = thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(ref mut h) = stderr_handle {
                let _ = h.read_to_end(&mut buf);
            }
            buf
        });

        let timeout_duration = Duration::from_millis(req.timeout_ms);
        let poll_interval = Duration::from_millis(25);
        let mut timed_out = false;
        let mut resource_violation = None;
        let mut exit_code = None;
        let mut error_msg = None;

        while timer.elapsed() < timeout_duration {
            match child.try_wait() {
                Ok(Some(status)) => {
                    exit_code = status.code();
                    break;
                }
                Ok(None) => {
                    thread::sleep(poll_interval);
                }
                Err(e) => {
                    error_msg = Some(format!("Error polling child process: {e}"));
                    break;
                }
            }
        }

        if exit_code.is_none() && timer.elapsed() >= timeout_duration {
            timed_out = true;
            resource_violation = Some(format!("TimeoutExceeded: {}ms", req.timeout_ms));
            error_msg = Some(format!(
                "Program execution exceeded maximum allowable runtime of {}ms and was terminated.",
                req.timeout_ms
            ));
            let _ = child.kill();
            let _ = child.wait();
        }

        let stdout_bytes = stdout_thread.join().unwrap_or_default();
        let stderr_bytes = stderr_thread.join().unwrap_or_default();
        let stdout_str = String::from_utf8_lossy(&stdout_bytes).to_string();
        let stderr_str = String::from_utf8_lossy(&stderr_bytes).to_string();

        let end_time = Utc::now();
        let duration_ms = timer.elapsed().as_millis();

        Ok(ExecutionResult {
            started: true,
            executable_path: req.binary_path,
            executable_hash,
            command_line_args: req.args,
            start_time,
            end_time,
            duration_ms,
            exit_code,
            stdout: stdout_str,
            stderr: stderr_str,
            timed_out,
            resource_violation,
            error_message: error_msg,
        })
    }
}
