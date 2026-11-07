//! Warm-AntiCheat Contest Builder Application Entry Point

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::env;
use std::path::PathBuf;
use warm_builder_core::{generate_contest_distribution, ContestBuildConfig};

#[derive(Debug, Serialize, Deserialize)]
pub struct BuildContestParams {
    pub title: String,
    pub organizer: String,
    pub description: Option<String>,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub prohibited_apps: Vec<String>,
    pub restricted_domains: Vec<String>,
    pub supported_platforms: Vec<String>,
    pub branding_theme: Option<String>,
    pub output_dir: Option<String>,
    #[serde(default)]
    pub enable_cpp_compiler: bool,
    #[serde(default)]
    pub participation_mode: Option<String>,
    #[serde(default)]
    pub account_count: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountsPreviewResponse {
    pub success: bool,
    pub count: usize,
    pub csv_content: String,
    pub html_content: String,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BuildContestResponse {
    pub success: bool,
    pub contest_id: String,
    pub root_dir: String,
    pub manifest_path: String,
    pub checksums_path: String,
    pub judge_private_key_path: String,
    pub error: Option<String>,
}

#[tauri::command]
fn get_builder_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[tauri::command]
fn generate_contest(params: BuildContestParams) -> BuildContestResponse {
    let start = params
        .start_time
        .and_then(|s| {
            DateTime::parse_from_rfc3339(&s)
                .ok()
                .map(|d| d.with_timezone(&Utc))
        })
        .unwrap_or_else(Utc::now);

    let end = params
        .end_time
        .and_then(|s| {
            DateTime::parse_from_rfc3339(&s)
                .ok()
                .map(|d| d.with_timezone(&Utc))
        })
        .unwrap_or_else(|| start + Duration::hours(5));

    let out_dir = params
        .output_dir
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("./dist"));

    let participation_mode = match params.participation_mode.as_deref() {
        Some("generated_accounts") => warm_core::ParticipationMode::GeneratedAccounts,
        _ => warm_core::ParticipationMode::NoAccounts,
    };
    let account_count = params.account_count.unwrap_or(0);

    let config = ContestBuildConfig {
        title: params.title,
        organizer: params.organizer,
        description: params.description.unwrap_or_else(|| "Contest".to_string()),
        start_time: start,
        end_time: end,
        prohibited_apps: params.prohibited_apps,
        restricted_domains: params.restricted_domains,
        supported_platforms: params.supported_platforms,
        branding_theme: params.branding_theme.unwrap_or_else(|| "dark".to_string()),
        output_base_dir: out_dir,
        enable_cpp_compiler: params.enable_cpp_compiler,
        participation_mode,
        account_count,
    };

    match generate_contest_distribution(&config) {
        Ok(bundle) => BuildContestResponse {
            success: true,
            contest_id: bundle.contest_id,
            root_dir: bundle.root_dir.to_string_lossy().to_string(),
            manifest_path: bundle
                .root_dir
                .join("manifests/contest_manifest.json")
                .to_string_lossy()
                .to_string(),
            checksums_path: bundle.checksums_path.to_string_lossy().to_string(),
            judge_private_key_path: bundle.judge_private_key_path.to_string_lossy().to_string(),
            error: None,
        },
        Err(e) => BuildContestResponse {
            success: false,
            contest_id: String::new(),
            root_dir: String::new(),
            manifest_path: String::new(),
            checksums_path: String::new(),
            judge_private_key_path: String::new(),
            error: Some(e.to_string()),
        },
    }
}

#[tauri::command]
fn generate_accounts_preview(
    contest_title: String,
    contest_id: String,
    count: usize,
) -> AccountsPreviewResponse {
    match warm_builder_core::generate_participant_accounts(&contest_id, count) {
        Ok((records, _)) => {
            let csv_content =
                warm_builder_core::export_credentials_csv(&contest_title, &contest_id, &records);
            let html_content = warm_builder_core::export_credentials_printable_html(
                &contest_title,
                &contest_id,
                &records,
            );
            AccountsPreviewResponse {
                success: true,
                count: records.len(),
                csv_content,
                html_content,
                error: None,
            }
        }
        Err(e) => AccountsPreviewResponse {
            success: false,
            count: 0,
            csv_content: String::new(),
            html_content: String::new(),
            error: Some(e.to_string()),
        },
    }
}

fn run_cli(args: &[String]) {
    let title = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| "GOCUP 1".to_string());
    let organizer = args
        .get(3)
        .cloned()
        .unwrap_or_else(|| "Sharif University Computer Society".to_string());
    let out_dir = args
        .get(4)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("./dist"));

    println!("[*] Building customized contest package...");
    println!("    Title:       {}", title);
    println!("    Organizer:   {}", organizer);
    println!("    Output Dir:  {}", out_dir.display());

    let start = Utc::now();
    let end = start + Duration::hours(5);

    let config = ContestBuildConfig {
        title,
        organizer,
        description: "Official Algorithmic Contest".to_string(),
        start_time: start,
        end_time: end,
        prohibited_apps: vec![
            "ollama".to_string(),
            "ollama.exe".to_string(),
            "lmstudio.exe".to_string(),
            "llama-cli.exe".to_string(),
        ],
        restricted_domains: vec![
            "chatgpt.com".to_string(),
            "claude.ai".to_string(),
            "gemini.google.com".to_string(),
        ],
        supported_platforms: vec![
            "windows".to_string(),
            "linux".to_string(),
            "macos".to_string(),
        ],
        branding_theme: "dark".to_string(),
        output_base_dir: out_dir,
        enable_cpp_compiler: args.iter().any(|a| a == "--enable-cpp-compiler"),
        participation_mode: warm_core::ParticipationMode::NoAccounts,
        account_count: 0,
    };

    match generate_contest_distribution(&config) {
        Ok(bundle) => {
            println!("\n[SUCCESS] Contest distribution bundle created successfully!");
            println!("    Contest ID:    {}", bundle.contest_id);
            println!("    Package Root:  {}", bundle.root_dir.display());
            println!(
                "    Manifest:      {}/manifests/contest_manifest.json",
                bundle.root_dir.display()
            );
            println!(
                "    Judge Key:     {}",
                bundle.judge_private_key_path.display()
            );
            println!("    Checksums:     {}", bundle.checksums_path.display());
        }
        Err(e) => {
            eprintln!("\n[ERROR] Contest build failed: {e}");
            std::process::exit(1);
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() > 1 && args[1] == "build" {
        run_cli(&args);
    } else if args.len() > 1 && (args[1] == "--help" || args[1] == "-h") {
        println!("Warm-AntiCheat Contest Builder");
        println!("Usage:");
        println!("  warm_builder_app build [TITLE] [ORGANIZER] [OUTPUT_DIR]");
        println!("  warm_builder_app [ui]");
    } else {
        // Run Desktop GUI via Tauri
        tauri::Builder::default()
            .invoke_handler(tauri::generate_handler![
                get_builder_version,
                generate_contest,
                generate_accounts_preview
            ])
            .run(tauri::generate_context!())
            .expect("Failed to run Warm-AntiCheat Contest Builder Desktop Application");
    }
}
