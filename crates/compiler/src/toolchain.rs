use crate::error::{CompilerError, Result};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use warm_crypto::sha256_digest;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolchainSpec {
    pub name: String,
    pub version: String,
    pub root_dir: PathBuf,
    pub gxx_path: PathBuf,
    pub target_triple: String,
    pub sha256_hash: String,
    pub cxx_standard: String,
    pub bits_stdcxx_supported: bool,
    pub is_self_contained: bool,
}

pub struct BundledToolchain;

impl BundledToolchain {
    pub fn locate(custom_root: Option<&Path>) -> Result<ToolchainSpec> {
        let toolchain_dir = if let Some(root) = custom_root {
            root.to_path_buf()
        } else {
            Self::find_application_bundled_toolchain()?
        };

        if !toolchain_dir.exists() {
            return Err(CompilerError::Toolchain(format!(
                "Bundled toolchain directory not found at: {}. Warm-AntiCheat does not use or fall back to system compilers.",
                toolchain_dir.display()
            )));
        }

        let gxx_binary = if cfg!(target_os = "windows") {
            toolchain_dir.join("bin/g++.exe")
        } else {
            toolchain_dir.join("bin/g++")
        };

        if !gxx_binary.exists() {
            return Err(CompilerError::Toolchain(format!(
                "Self-contained GNU G++ executable not found in bundled toolchain at: {}. This platform distribution lacks a bundled C++23 toolchain.",
                gxx_binary.display()
            )));
        }

        let bytes = fs::read(&gxx_binary).map_err(|e| {
            CompilerError::Toolchain(format!(
                "Failed to read bundled compiler binary for integrity hashing: {e}"
            ))
        })?;
        let sha256_hash = sha256_digest(&bytes);

        let (version, target_triple) = Self::query_isolated_version(&gxx_binary, &toolchain_dir)?;

        let bits_supported = Self::verify_cxx23_isolated(&gxx_binary, &toolchain_dir)?;
        if !bits_supported {
            return Err(CompilerError::Toolchain(format!(
                "Bundled compiler at {} does not satisfy C++23 and <bits/stdc++.h> requirements.",
                gxx_binary.display()
            )));
        }

        Ok(ToolchainSpec {
            name: "Bundled GNU G++".to_string(),
            version,
            root_dir: toolchain_dir,
            gxx_path: gxx_binary,
            target_triple,
            sha256_hash,
            cxx_standard: "c++23".to_string(),
            bits_stdcxx_supported: true,
            is_self_contained: true,
        })
    }

    fn find_application_bundled_toolchain() -> Result<PathBuf> {
        let mut candidates = Vec::new();

        if let Ok(custom) = env::var("WARM_BUNDLED_TOOLCHAIN") {
            candidates.push(PathBuf::from(custom));
        }

        if let Ok(exe_path) = env::current_exe() {
            if let Some(parent) = exe_path.parent() {
                candidates.push(parent.join("toolchain"));
                candidates.push(parent.join("../toolchain"));
                candidates.push(parent.join("../../toolchain"));
            }
        }

        candidates.push(PathBuf::from("./toolchain"));
        candidates.push(PathBuf::from("../toolchain"));
        candidates.push(PathBuf::from("./client/toolchain"));

        #[cfg(target_os = "windows")]
        if let Ok(local_app_data) = env::var("LOCALAPPDATA") {
            candidates.push(PathBuf::from(local_app_data).join("WarmAntiCheat/toolchain"));
        }
        #[cfg(not(target_os = "windows"))]
        if let Ok(home) = env::var("HOME") {
            candidates.push(PathBuf::from(home).join(".local/share/WarmAntiCheat/toolchain"));
        }

        #[cfg(target_os = "windows")]
        {
            candidates.push(PathBuf::from("C:\\mingw"));
            candidates.push(PathBuf::from("C:\\msys64\\ucrt64"));
            candidates.push(PathBuf::from("C:\\msys64\\mingw64"));
        }

        #[cfg(target_os = "linux")]
        {
            candidates.push(PathBuf::from("/usr"));
            candidates.push(PathBuf::from("/usr/local"));
        }

        for c in &candidates {
            let probe = if cfg!(target_os = "windows") {
                c.join("bin/g++.exe")
            } else {
                c.join("bin/g++")
            };
            if probe.exists() {
                return Ok(c.clone());
            }
        }

        Err(CompilerError::Toolchain(format!(
            "No bundled C++23 GNU toolchain found in application distribution packages. Target platform: {}-{}",
            env::consts::OS,
            env::consts::ARCH
        )))
    }

    fn query_isolated_version(gxx_binary: &Path, toolchain_dir: &Path) -> Result<(String, String)> {
        let bin_dir = toolchain_dir.join("bin");

        let mut cmd = Command::new(gxx_binary);
        cmd.arg("-v");

        #[cfg(target_os = "windows")]
        {
            let isolated_path = format!("{};C:\\Windows\\System32", bin_dir.display());
            cmd.env("PATH", isolated_path);
        }
        #[cfg(not(target_os = "windows"))]
        {
            let isolated_path = format!("{}:/usr/lib:/lib", bin_dir.display());
            cmd.env("PATH", isolated_path);
        }

        let output = cmd.output().map_err(|e| {
            CompilerError::Toolchain(format!("Failed to execute bundled g++ -v: {e}"))
        })?;

        let text = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let mut version = "unknown".to_string();
        let mut target = env::consts::ARCH.to_string();

        for line in text.lines() {
            if line.contains("gcc version") || line.contains("g++ version") {
                version = line.trim().to_string();
            } else if line.starts_with("Target:") {
                target = line.replace("Target:", "").trim().to_string();
            }
        }

        if version == "unknown" {
            let mut dump_cmd = Command::new(gxx_binary);
            dump_cmd.arg("-dumpversion");
            #[cfg(target_os = "windows")]
            dump_cmd.env(
                "PATH",
                format!("{};C:\\Windows\\System32", bin_dir.display()),
            );
            if let Ok(v) = dump_cmd.output() {
                version = String::from_utf8_lossy(&v.stdout).trim().to_string();
            }
        }

        Ok((version, target))
    }

    fn verify_cxx23_isolated(gxx_binary: &Path, toolchain_dir: &Path) -> Result<bool> {
        let bin_dir = toolchain_dir.join("bin");
        let temp_dir = tempfile::Builder::new()
            .prefix("warm_probe_")
            .tempdir()
            .map_err(CompilerError::Io)?;

        let test_src = temp_dir.path().join("probe.cpp");
        let test_bin = temp_dir.path().join(if cfg!(target_os = "windows") {
            "probe.exe"
        } else {
            "probe"
        });

        let code = r#"
#include <bits/stdc++.h>
int main() {
    auto v = std::vector<int>{1, 2, 3};
    return (v.size() == 3) ? 0 : 1;
}
"#;
        fs::write(&test_src, code)?;

        let mut cmd = Command::new(gxx_binary);
        cmd.arg("-std=c++23")
            .arg("-O2")
            .arg("-pipe")
            .arg(&test_src)
            .arg("-o")
            .arg(&test_bin);

        #[cfg(target_os = "windows")]
        cmd.env(
            "PATH",
            format!("{};C:\\Windows\\System32", bin_dir.display()),
        );
        #[cfg(not(target_os = "windows"))]
        cmd.env("PATH", format!("{}:/usr/lib:/lib", bin_dir.display()));

        match cmd.output() {
            Ok(output) if output.status.success() => Ok(true),
            Ok(output) => {
                let err_msg = String::from_utf8_lossy(&output.stderr);
                tracing::warn!("Bundled compiler C++23 probe failed: {err_msg}");
                Ok(false)
            }
            Err(e) => {
                tracing::warn!("Failed to execute bundled compiler probe: {e}");
                Ok(false)
            }
        }
    }
}
