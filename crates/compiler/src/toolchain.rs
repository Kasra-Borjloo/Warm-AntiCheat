use crate::error::{CompilerError, Result};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use warm_crypto::sha256_digest;

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

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
        let (toolchain_dir, gxx_binary) = if let Some(root) = custom_root {
            let probe_bin = if cfg!(target_os = "windows") {
                root.join("bin").join("g++.exe")
            } else {
                root.join("bin").join("g++")
            };
            let probe_direct = if cfg!(target_os = "windows") {
                root.join("g++.exe")
            } else {
                root.join("g++")
            };
            if probe_bin.exists() {
                (root.to_path_buf(), probe_bin)
            } else if probe_direct.exists() {
                (root.parent().unwrap_or(root).to_path_buf(), probe_direct)
            } else {
                return Err(CompilerError::Toolchain(format!(
                    "Compiler binary not found in specified custom root: {}",
                    root.display()
                )));
            }
        } else {
            Self::find_application_bundled_toolchain()?
        };

        let bytes = fs::read(&gxx_binary).map_err(|e| {
            CompilerError::Toolchain(format!(
                "Failed to read compiler binary for integrity hashing: {e}"
            ))
        })?;
        let sha256_hash = sha256_digest(&bytes);

        let (version, target_triple) = Self::query_isolated_version(&gxx_binary, &toolchain_dir)?;

        let (cxx_standard, bits_supported) =
            Self::verify_cxx_isolated(&gxx_binary, &toolchain_dir)?;

        Ok(ToolchainSpec {
            name: "GNU G++".to_string(),
            version,
            root_dir: toolchain_dir,
            gxx_path: gxx_binary,
            target_triple,
            sha256_hash,
            cxx_standard,
            bits_stdcxx_supported: bits_supported,
            is_self_contained: true,
        })
    }

    fn find_application_bundled_toolchain() -> Result<(PathBuf, PathBuf)> {
        let mut candidates = Vec::new();

        if let Ok(custom) = env::var("WARM_BUNDLED_TOOLCHAIN") {
            candidates.push(PathBuf::from(custom));
        }

        if let Ok(exe_path) = env::current_exe() {
            if let Some(parent) = exe_path.parent() {
                candidates.push(parent.join("toolchain"));
                candidates.push(parent.join("bin").join("toolchain"));
                candidates.push(parent.join("../toolchain"));
                candidates.push(parent.join("../../toolchain"));
                candidates.push(parent.join("client/windows/toolchain"));
                candidates.push(parent.join("client/linux/toolchain"));
                candidates.push(parent.join("client/macos/toolchain"));
                candidates.push(parent.join("client/toolchain"));
                candidates.push(parent.to_path_buf());
            }
        }

        candidates.push(PathBuf::from("./toolchain"));
        candidates.push(PathBuf::from("./bin/toolchain"));
        candidates.push(PathBuf::from("../toolchain"));
        candidates.push(PathBuf::from("./client/windows/toolchain"));
        candidates.push(PathBuf::from("./client/linux/toolchain"));
        candidates.push(PathBuf::from("./client/macos/toolchain"));
        candidates.push(PathBuf::from("./client/toolchain"));
        candidates.push(PathBuf::from("./bin"));

        #[cfg(target_os = "windows")]
        if let Ok(local_app_data) = env::var("LOCALAPPDATA") {
            let local_path = PathBuf::from(&local_app_data);
            candidates.push(local_path.join("WarmAntiCheat/toolchain"));
            candidates.push(local_path.join("Programs/WarmAntiCheat/toolchain"));
        }

        #[cfg(not(target_os = "windows"))]
        if let Ok(home) = env::var("HOME") {
            candidates.push(PathBuf::from(home).join(".local/share/WarmAntiCheat/toolchain"));
            candidates.push(
                PathBuf::from(home).join("Library/Application Support/WarmAntiCheat/toolchain"),
            );
        }

        for c in &candidates {
            let probe_bin = if cfg!(target_os = "windows") {
                c.join("bin").join("g++.exe")
            } else {
                c.join("bin").join("g++")
            };
            if probe_bin.exists() {
                return Ok((c.clone(), probe_bin));
            }

            let probe_direct = if cfg!(target_os = "windows") {
                c.join("g++.exe")
            } else {
                c.join("g++")
            };
            if probe_direct.exists() {
                let root = c.parent().unwrap_or(c).to_path_buf();
                return Ok((root, probe_direct));
            }
        }

        let mut fallback_candidates = Vec::new();

        #[cfg(target_os = "windows")]
        {
            let mut where_cmd = Command::new("where.exe");
            where_cmd.creation_flags(0x08000000);
            if let Ok(output) = where_cmd.arg("g++").output() {
                if output.status.success() {
                    let out_str = String::from_utf8_lossy(&output.stdout);
                    for line in out_str.lines() {
                        let trimmed = line.trim();
                        if !trimmed.is_empty() {
                            let p = PathBuf::from(trimmed);
                            if p.exists() {
                                if let Some(bin_dir) = p.parent() {
                                    fallback_candidates.push(bin_dir.to_path_buf());
                                    if let Some(root_dir) = bin_dir.parent() {
                                        fallback_candidates.push(root_dir.to_path_buf());
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if let Ok(path_var) = env::var("PATH") {
                for part in path_var.split(';') {
                    let p = PathBuf::from(part.trim());
                    if p.exists() {
                        fallback_candidates.push(p.clone());
                        if let Some(parent) = p.parent() {
                            fallback_candidates.push(parent.to_path_buf());
                        }
                    }
                }
            }

            if let Ok(local_app_data) = env::var("LOCALAPPDATA") {
                let local_path = PathBuf::from(&local_app_data);
                let winget_dir = local_path.join("Microsoft/WinGet/Packages");
                if winget_dir.exists() {
                    if let Ok(entries) = fs::read_dir(&winget_dir) {
                        for entry in entries.flatten() {
                            let ep = entry.path();
                            if ep.is_dir() {
                                fallback_candidates.push(ep.join("mingw64"));
                                fallback_candidates.push(ep.join("mingw32"));
                                fallback_candidates.push(ep.join("bin"));
                                fallback_candidates.push(ep);
                            }
                        }
                    }
                }
            }

            fallback_candidates.push(PathBuf::from("C:\\mingw"));
            fallback_candidates.push(PathBuf::from("C:\\MinGW"));
            fallback_candidates.push(PathBuf::from("C:\\mingw64"));
            fallback_candidates.push(PathBuf::from("C:\\MinGW64"));
            fallback_candidates.push(PathBuf::from("C:\\mingw-w64"));
            fallback_candidates.push(PathBuf::from("C:\\msys64\\ucrt64"));
            fallback_candidates.push(PathBuf::from("C:\\msys64\\mingw64"));
            fallback_candidates.push(PathBuf::from("C:\\msys64\\clang64"));
            fallback_candidates.push(PathBuf::from("C:\\w64devkit"));
            fallback_candidates.push(PathBuf::from("C:\\winlibs"));
            fallback_candidates.push(PathBuf::from("C:\\winlibs-x86_64"));
        }

        #[cfg(not(target_os = "windows"))]
        {
            if let Ok(output) = Command::new("which").arg("g++").output() {
                if output.status.success() {
                    let out_str = String::from_utf8_lossy(&output.stdout);
                    let trimmed = out_str.trim();
                    if !trimmed.is_empty() {
                        let p = PathBuf::from(trimmed);
                        if let Some(bin_dir) = p.parent() {
                            fallback_candidates.push(bin_dir.to_path_buf());
                            if let Some(root_dir) = bin_dir.parent() {
                                fallback_candidates.push(root_dir.to_path_buf());
                            }
                        }
                    }
                }
            }

            if let Ok(path_var) = env::var("PATH") {
                for part in path_var.split(':') {
                    let p = PathBuf::from(part.trim());
                    if p.exists() {
                        fallback_candidates.push(p.clone());
                        if let Some(parent) = p.parent() {
                            fallback_candidates.push(parent.to_path_buf());
                        }
                    }
                }
            }

            fallback_candidates.push(PathBuf::from("/usr"));
            fallback_candidates.push(PathBuf::from("/usr/local"));
            fallback_candidates.push(PathBuf::from("/opt/gcc"));
            fallback_candidates.push(PathBuf::from("/opt"));
            fallback_candidates.push(PathBuf::from("/opt/homebrew"));
            fallback_candidates.push(PathBuf::from("/run/current-system/sw"));
        }

        for c in &fallback_candidates {
            let probe_bin = if cfg!(target_os = "windows") {
                c.join("bin").join("g++.exe")
            } else {
                c.join("bin").join("g++")
            };
            if probe_bin.exists() {
                return Ok((c.clone(), probe_bin));
            }

            let probe_direct = if cfg!(target_os = "windows") {
                c.join("g++.exe")
            } else {
                c.join("g++")
            };
            if probe_direct.exists() {
                let root = c.parent().unwrap_or(c).to_path_buf();
                return Ok((root, probe_direct));
            }
        }

        Err(CompilerError::Toolchain(format!(
            "No GNU C++ toolchain found in application distribution packages or system paths. Target platform: {}-{}",
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
            cmd.creation_flags(0x08000000);
            let isolated_path = format!("{};C:\\Windows\\System32", bin_dir.display());
            cmd.env("PATH", isolated_path);
        }
        #[cfg(not(target_os = "windows"))]
        {
            let isolated_path = format!("{}:/usr/bin:/bin", bin_dir.display());
            cmd.env("PATH", isolated_path);
        }

        let output = cmd
            .output()
            .map_err(|e| CompilerError::Toolchain(format!("Failed to execute compiler -v: {e}")))?;

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
            {
                dump_cmd.creation_flags(0x08000000);
                dump_cmd.env(
                    "PATH",
                    format!("{};C:\\Windows\\System32", bin_dir.display()),
                );
            }
            if let Ok(v) = dump_cmd.output() {
                version = String::from_utf8_lossy(&v.stdout).trim().to_string();
            }
        }

        Ok((version, target))
    }

    fn verify_cxx_isolated(gxx_binary: &Path, toolchain_dir: &Path) -> Result<(String, bool)> {
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

        let code_bits = r#"
#include <bits/stdc++.h>
int main() {
    auto v = std::vector<int>{1, 2, 3};
    return (v.size() == 3) ? 0 : 1;
}
"#;
        fs::write(&test_src, code_bits)?;

        for std_flag in &["c++23", "c++2b", "c++20"] {
            let mut cmd = Command::new(gxx_binary);
            #[cfg(target_os = "windows")]
            cmd.creation_flags(0x08000000);

            cmd.arg(format!("-std={std_flag}"))
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
            cmd.env("PATH", format!("{}:/usr/bin:/bin", bin_dir.display()));

            if let Ok(output) = cmd.output() {
                if output.status.success() {
                    return Ok((std_flag.to_string(), true));
                }
            }
        }

        let code_std = r#"
#include <vector>
#include <iostream>
int main() {
    std::vector<int> v = {1, 2, 3};
    return (v.size() == 3) ? 0 : 1;
}
"#;
        fs::write(&test_src, code_std)?;

        for std_flag in &["c++23", "c++2b", "c++20"] {
            let mut cmd = Command::new(gxx_binary);
            #[cfg(target_os = "windows")]
            cmd.creation_flags(0x08000000);

            cmd.arg(format!("-std={std_flag}"))
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
            cmd.env("PATH", format!("{}:/usr/bin:/bin", bin_dir.display()));

            if let Ok(output) = cmd.output() {
                if output.status.success() {
                    return Ok((std_flag.to_string(), false));
                }
            }
        }

        Err(CompilerError::Toolchain(format!(
            "Compiler at {} does not satisfy minimum C++20 standard requirements.",
            gxx_binary.display()
        )))
    }
}
