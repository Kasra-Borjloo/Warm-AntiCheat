//! Warm-AntiCheat Contest Builder Application Entry Point

use chrono::{Duration, Utc};
use std::env;
use std::path::PathBuf;
use warm_builder_core::{generate_contest_distribution, ContestBuildConfig};

fn main() {
    let args: Vec<String> = env::args().collect();

    println!("=======================================================");
    println!(
        "   Warm-AntiCheat Contest Builder v{}",
        env!("CARGO_PKG_VERSION")
    );
    println!("   Offline-First Competition Integrity Framework");
    println!("=======================================================\n");

    if args.len() > 1 && args[1] == "build" {
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
    } else {
        println!("Usage:");
        println!("  warm_builder_app build [TITLE] [ORGANIZER] [OUTPUT_DIR]");
        println!("  warm_builder_app ui\n");
        println!("Example:");
        println!("  warm_builder_app build \"GOCUP 1\" \"Sharif Org\" ./dist\n");
        println!("Web UI assets available at: apps/builder/ui/index.html");
    }
}
