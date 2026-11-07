use crate::error::{CompilerError, Result};
use crate::toolchain::ToolchainSpec;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;
use warm_crypto::sha256_digest;

/// Input parameters for a C++ compilation attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilationRequest {
    pub source_path: PathBuf,
    pub source_code: Option<String>,
    pub output_dir: Option<PathBuf>,
    pub optimization_level: Option<String>,
    pub standard: Option<String>,
    pub extra_args: Vec<String>,
}

impl Default for CompilationRequest {
    fn default() -> Self {
        Self {
            source_path: PathBuf::from("solution.cpp"),
            source_code: None,
            output_dir: None,
            optimization_level: Some("-O2".to_string()),
            standard: Some("-std=c++23".to_string()),
            extra_args: vec!["-pipe".to_string()],
        }
    }
}

/// Output data and forensic artifacts from a compilation attempt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompilationResult {
    pub success: bool,
    pub source_path: PathBuf,
    pub source_sha256: String,
    pub source_snapshot: String,
    pub compiler_version: String,
    pub toolchain_hash: String,
    pub compilation_args: Vec<String>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub duration_ms: u128,
    pub exit_code: Option<i32>,
    pub diagnostics: String,
    pub output_binary_path: Option<PathBuf>,
    pub output_binary_hash: Option<String>,
}

pub struct CompilerEngine {
    toolchain: ToolchainSpec,
}

impl CompilerEngine {
    pub fn new(toolchain: ToolchainSpec) -> Self {
        Self { toolchain }
    }

    pub fn toolchain(&self) -> &ToolchainSpec {
        &self.toolchain
    }

    /// Securely compile a C++ source file using the bundled, isolated GNU G++ compiler.
    pub fn compile(&self, req: CompilationRequest) -> Result<CompilationResult> {
        let start_time = Utc::now();
        let timer = Instant::now();

        // 1. Resolve source code and compute cryptographic hash snapshot
        let (source_file, source_snapshot, source_sha256) = self.prepare_source_file(&req)?;

        // 2. Prepare safe isolated output directory
        let temp_dir = if let Some(ref d) = req.output_dir {
            fs::create_dir_all(d)?;
            None
        } else {
            let td = tempfile::Builder::new()
                .prefix("warm_build_")
                .tempdir()
                .map_err(CompilerError::Io)?;
            Some(td)
        };

        let target_dir = req
            .output_dir
            .as_deref()
            .unwrap_or_else(|| temp_dir.as_ref().unwrap().path());

        let out_ext = if cfg!(target_os = "windows") {
            "exe"
        } else {
            "out"
        };
        let output_binary =
            target_dir.join(format!("contest_bin_{}.{}", uuid::Uuid::new_v4(), out_ext));

        // 3. Assemble arguments safely without shell interpolation
        let mut args = Vec::new();
        args.push(req.standard.unwrap_or_else(|| "-std=c++23".to_string()));
        args.push(req.optimization_level.unwrap_or_else(|| "-O2".to_string()));

        for extra in req.extra_args {
            if !extra.trim().is_empty() {
                args.push(extra.trim().to_string());
            }
        }

        args.push(source_file.to_string_lossy().to_string());
        args.push("-o".to_string());
        args.push(output_binary.to_string_lossy().to_string());

        // 4. Configure command with completely isolated process environment
        let mut cmd = Command::new(&self.toolchain.gxx_path);
        cmd.args(&args);

        let bin_dir = self.toolchain.root_dir.join("bin");
        #[cfg(target_os = "windows")]
        cmd.env(
            "PATH",
            format!("{};C:\\Windows\\System32", bin_dir.display()),
        );
        #[cfg(not(target_os = "windows"))]
        cmd.env("PATH", format!("{}:/usr/lib:/lib", bin_dir.display()));

        let compile_output = cmd
            .output()
            .map_err(|e| CompilerError::Toolchain(format!("Failed to execute bundled g++: {e}")))?;

        let end_time = Utc::now();
        let duration_ms = timer.elapsed().as_millis();
        let exit_code = compile_output.status.code();
        let is_success = compile_output.status.success();

        let stdout_str = String::from_utf8_lossy(&compile_output.stdout);
        let stderr_str = String::from_utf8_lossy(&compile_output.stderr);
        let diagnostics = format!("{}{}", stdout_str, stderr_str).trim().to_string();

        let (binary_path, binary_hash) = if is_success && output_binary.exists() {
            let bin_bytes = fs::read(&output_binary).map_err(CompilerError::Io)?;
            let hash = sha256_digest(&bin_bytes);
            (Some(output_binary), Some(hash))
        } else {
            (None, None)
        };

        if let Some(td) = temp_dir {
            if is_success {
                std::mem::forget(td);
            }
        }

        Ok(CompilationResult {
            success: is_success,
            source_path: req.source_path,
            source_sha256,
            source_snapshot,
            compiler_version: self.toolchain.version.clone(),
            toolchain_hash: self.toolchain.sha256_hash.clone(),
            compilation_args: args,
            start_time,
            end_time,
            duration_ms,
            exit_code,
            diagnostics,
            output_binary_path: binary_path,
            output_binary_hash: binary_hash,
        })
    }

    fn prepare_source_file(&self, req: &CompilationRequest) -> Result<(PathBuf, String, String)> {
        if let Some(ref code) = req.source_code {
            let temp_src = tempfile::Builder::new()
                .prefix("warm_src_")
                .suffix(".cpp")
                .tempfile()
                .map_err(CompilerError::Io)?;
            let (_, path) = temp_src.keep().map_err(|e| CompilerError::Io(e.error))?;
            fs::write(&path, code)?;
            let hash = sha256_digest(code.as_bytes());
            Ok((path, code.clone(), hash))
        } else if req.source_path.exists() {
            let bytes = fs::read(&req.source_path).map_err(|e| {
                CompilerError::Source(format!(
                    "Failed to read source file {}: {e}",
                    req.source_path.display()
                ))
            })?;
            let hash = sha256_digest(&bytes);
            let snapshot = String::from_utf8_lossy(&bytes).to_string();
            Ok((req.source_path.clone(), snapshot, hash))
        } else {
            Err(CompilerError::Source(format!(
                "Source file does not exist: {}",
                req.source_path.display()
            )))
        }
    }
}
