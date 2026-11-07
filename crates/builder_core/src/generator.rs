use crate::manifest::{ContestExportAuthToken, ContestManifest, SignedContestManifest};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use warm_core::{Contest, Result, WarmError};
use warm_crypto::{
    compute_fingerprint, sha256_digest, EvidenceEncryptionKeypair, ManifestSigningKeypair,
};
use warm_policies::{AppPolicy, BrowserPolicy, MonitoringPolicy};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContestBuildConfig {
    pub title: String,
    pub organizer: String,
    pub description: String,
    #[serde(default)]
    pub start_time: Option<DateTime<Utc>>,
    #[serde(default)]
    pub end_time: Option<DateTime<Utc>>,
    pub prohibited_apps: Vec<String>,
    pub restricted_domains: Vec<String>,
    pub supported_platforms: Vec<String>,
    pub branding_theme: String,
    pub output_base_dir: PathBuf,
    #[serde(default)]
    pub enable_cpp_compiler: bool,
    #[serde(default)]
    pub participation_mode: warm_core::ParticipationMode,
    #[serde(default)]
    pub account_count: usize,
}

#[derive(Debug, Clone)]
pub struct ContestDistBundle {
    pub contest_id: String,
    pub root_dir: PathBuf,
    pub signed_manifest: SignedContestManifest,
    pub judge_private_key_path: PathBuf,
    pub manifest_signing_key_priv_path: PathBuf,
    pub checksums_path: PathBuf,
    pub participant_client_path: Option<PathBuf>,
}

const WEBVIEW2_LOADER_X64: &[u8] = include_bytes!("../../../assets/windows/x64/WebView2Loader.dll");

fn locate_participant_binary() -> Option<PathBuf> {
    let mut candidates = Vec::new();

    if let Ok(p) = std::env::var("WARM_PARTICIPANT_BIN") {
        candidates.push(PathBuf::from(p));
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("warm_participant_app.exe"));
            candidates.push(dir.join("warm_participant_app"));
            candidates.push(dir.join("bin/warm_participant_app.exe"));
            candidates.push(dir.join("bin/warm_participant_app"));
            candidates.push(dir.join("../warm_participant_app.exe"));
            candidates.push(dir.join("../warm_participant_app"));
            candidates.push(dir.join("../bin/warm_participant_app.exe"));
            candidates.push(dir.join("../bin/warm_participant_app"));
        }
    }

    candidates.push(PathBuf::from(
        "C:/warm_target/debug/warm_participant_app.exe",
    ));
    candidates.push(PathBuf::from(
        "C:/warm_target/release/warm_participant_app.exe",
    ));
    candidates.push(PathBuf::from("./target/debug/warm_participant_app.exe"));
    candidates.push(PathBuf::from("./target/release/warm_participant_app.exe"));
    candidates.push(PathBuf::from("../target/debug/warm_participant_app.exe"));
    candidates.push(PathBuf::from("../target/release/warm_participant_app.exe"));
    candidates.push(PathBuf::from("../../target/debug/warm_participant_app.exe"));
    candidates.push(PathBuf::from(
        "../../target/release/warm_participant_app.exe",
    ));
    candidates.push(PathBuf::from("./target/debug/warm_participant_app"));
    candidates.push(PathBuf::from("./target/release/warm_participant_app"));
    candidates.push(PathBuf::from("../target/debug/warm_participant_app"));
    candidates.push(PathBuf::from("../target/release/warm_participant_app"));
    candidates.push(PathBuf::from("../../target/debug/warm_participant_app"));
    candidates.push(PathBuf::from("../../target/release/warm_participant_app"));

    candidates.into_iter().find(|c| c.exists() && c.is_file())
}

fn locate_judge_binary() -> Option<PathBuf> {
    let mut candidates = Vec::new();

    if let Ok(p) = std::env::var("WARM_JUDGE_BIN") {
        candidates.push(PathBuf::from(p));
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("warm_judge_app.exe"));
            candidates.push(dir.join("warm_judge_app"));
            candidates.push(dir.join("bin/warm_judge_app.exe"));
            candidates.push(dir.join("bin/warm_judge_app"));
            candidates.push(dir.join("../warm_judge_app.exe"));
            candidates.push(dir.join("../warm_judge_app"));
            candidates.push(dir.join("../bin/warm_judge_app.exe"));
            candidates.push(dir.join("../bin/warm_judge_app"));
        }
    }

    candidates.push(PathBuf::from("C:/warm_target/debug/warm_judge_app.exe"));
    candidates.push(PathBuf::from("C:/warm_target/release/warm_judge_app.exe"));
    candidates.push(PathBuf::from("./target/debug/warm_judge_app.exe"));
    candidates.push(PathBuf::from("./target/release/warm_judge_app.exe"));
    candidates.push(PathBuf::from("../target/debug/warm_judge_app.exe"));
    candidates.push(PathBuf::from("../target/release/warm_judge_app.exe"));
    candidates.push(PathBuf::from("../../target/debug/warm_judge_app.exe"));
    candidates.push(PathBuf::from("../../target/release/warm_judge_app.exe"));
    candidates.push(PathBuf::from("./target/debug/warm_judge_app"));
    candidates.push(PathBuf::from("./target/release/warm_judge_app"));
    candidates.push(PathBuf::from("../target/debug/warm_judge_app"));
    candidates.push(PathBuf::from("../target/release/warm_judge_app"));
    candidates.push(PathBuf::from("../../target/debug/warm_judge_app"));
    candidates.push(PathBuf::from("../../target/release/warm_judge_app"));

    candidates.into_iter().find(|c| c.exists() && c.is_file())
}

pub fn generate_contest_distribution(config: &ContestBuildConfig) -> Result<ContestDistBundle> {
    let contest = Contest::with_times(
        &config.title,
        &config.organizer,
        &config.description,
        config.start_time,
        config.end_time,
    )?;

    let contest_dir = config.output_base_dir.join(&contest.id);
    let client_dir = contest_dir.join("client");
    let client_win_dir = client_dir.join("windows");
    let client_linux_dir = client_dir.join("linux");
    let client_macos_dir = client_dir.join("macos");
    let judge_dir = contest_dir.join("judge");
    let judge_keys_dir = judge_dir.join("keys");
    let judge_usb_dir = judge_dir.join("usb_token");
    let manifests_dir = contest_dir.join("manifests");
    let config_dir = contest_dir.join("configuration");
    let checksums_dir = contest_dir.join("checksums");

    for d in [
        &contest_dir,
        &client_dir,
        &client_win_dir,
        &client_linux_dir,
        &client_macos_dir,
        &judge_dir,
        &judge_keys_dir,
        &judge_usb_dir,
        &manifests_dir,
        &config_dir,
        &checksums_dir,
    ] {
        fs::create_dir_all(d).map_err(|e| {
            WarmError::Io(format!("Failed to create directory {}: {e}", d.display()))
        })?;
    }

    let signing_keypair = ManifestSigningKeypair::generate();
    let judge_keypair = EvidenceEncryptionKeypair::generate();

    let app_policy = if config.prohibited_apps.is_empty() {
        AppPolicy::default()
    } else {
        AppPolicy::new(config.prohibited_apps.clone())
    };

    let browser_policy = if config.restricted_domains.is_empty() {
        BrowserPolicy::default()
    } else {
        BrowserPolicy::new(config.restricted_domains.clone())
    };

    let monitoring_policy = MonitoringPolicy {
        app_policy,
        browser_policy,
        heartbeat_interval_secs: 15,
        max_interruption_gap_secs: 60,
        retention_days: contest.retention_days,
        enable_cpp_compiler: config.enable_cpp_compiler,
    };

    if config.enable_cpp_compiler {
        let toolchain_dir = client_dir.join("toolchain");
        let _ = fs::create_dir_all(&toolchain_dir);
        let spec_file = toolchain_dir.join("toolchain_manifest.json");
        let spec_json = serde_json::json!({
            "name": "GNU GCC / G++ C++23 Toolchain",
            "version": "14.2.0",
            "cxx_standard": "c++23",
            "bits_stdcxx_supported": true,
            "offline_ready": true,
            "platforms": config.supported_platforms
        });
        let _ = fs::write(
            &spec_file,
            serde_json::to_string_pretty(&spec_json).unwrap(),
        );
    }

    let (account_config, judge_csv, judge_html, judge_pdf) = if config.participation_mode
        == warm_core::ParticipationMode::GeneratedAccounts
        && config.account_count > 0
    {
        let (records, verifiers) =
            crate::accounts::generate_participant_accounts(&contest.id, config.account_count)?;
        let csv = crate::accounts::export_credentials_csv(&contest.title, &contest.id, &records);
        let html = crate::accounts::export_credentials_printable_html(
            &contest.title,
            &contest.id,
            &records,
        );
        let pdf = crate::accounts::export_credentials_pdf(&contest.title, &contest.id, &records);
        (
            warm_core::AccountModeConfig {
                mode: warm_core::ParticipationMode::GeneratedAccounts,
                account_count: config.account_count,
                verifiers,
            },
            Some(csv),
            Some(html),
            Some(pdf),
        )
    } else {
        (warm_core::AccountModeConfig::default(), None, None, None)
    };

    if let Some(csv) = judge_csv {
        let _ = fs::write(judge_dir.join("credentials.csv"), csv);
    }
    if let Some(html) = judge_html {
        let _ = fs::write(judge_dir.join("credentials.html"), html);
    }
    if let Some(pdf) = judge_pdf {
        let _ = fs::write(judge_dir.join("credentials.pdf"), pdf);
    }

    let usb_token = ContestExportAuthToken {
        contest_id: contest.id.clone(),
        contest_uuid: contest.uuid,
        purpose: "CONTEST_LOG_EXPORT_AUTHORIZATION".to_string(),
        created_at: Utc::now(),
        nonce: uuid::Uuid::new_v4().to_string(),
    };
    let signed_token = usb_token.sign(&signing_keypair)?;
    let token_json = serde_json::to_string_pretty(&signed_token)
        .map_err(|e| WarmError::Serialization(e.to_string()))?;
    fs::write(judge_usb_dir.join("warm_export_auth.token"), token_json)
        .map_err(|e| WarmError::Io(e.to_string()))?;

    let mut binary_checksums = BTreeMap::new();
    let mut copied_participant_client = None;

    if let Some(src_bin) = locate_participant_binary() {
        if let Ok(bin_bytes) = fs::read(&src_bin) {
            let is_pe = bin_bytes.starts_with(b"MZ");
            if is_pe {
                let win_exe_target = client_win_dir.join("Warm-AntiCheat-Participant.exe");
                let _ = fs::write(&win_exe_target, &bin_bytes);
                let win_hash = sha256_digest(&bin_bytes);
                binary_checksums.insert("windows-x86_64".to_string(), win_hash);
                copied_participant_client = Some(win_exe_target);

                let bat_content =
                    "@echo off\r\nstart \"\" \"%~dp0Warm-AntiCheat-Participant.exe\"\r\n";
                let _ = fs::write(client_win_dir.join("Run-Contest.bat"), bat_content);
                let _ = fs::write(
                    client_win_dir.join("WebView2Loader.dll"),
                    WEBVIEW2_LOADER_X64,
                );
            } else {
                let linux_exe_target = client_linux_dir.join("warm_participant_app");
                let _ = fs::write(&linux_exe_target, &bin_bytes);
                let hash = sha256_digest(&bin_bytes);
                binary_checksums.insert("linux-x86_64".to_string(), hash);
                copied_participant_client = Some(linux_exe_target);
            }
        }
    } else {
        binary_checksums.insert("windows-x86_64".to_string(), "PENDING_BUILD".to_string());
    }

    if !binary_checksums.contains_key("linux-x86_64") {
        binary_checksums.insert("linux-x86_64".to_string(), "PENDING_BUILD".to_string());
    }
    binary_checksums.insert("macos-universal".to_string(), "PENDING_BUILD".to_string());

    if let Some(judge_bin) = locate_judge_binary() {
        if let Ok(judge_bytes) = fs::read(&judge_bin) {
            let is_pe = judge_bytes.starts_with(b"MZ");
            if is_pe {
                let win_judge_target = judge_dir.join("Warm-AntiCheat-Judge.exe");
                let _ = fs::write(&win_judge_target, &judge_bytes);
                let bat_content = "@echo off\r\nstart \"\" \"%~dp0Warm-AntiCheat-Judge.exe\"\r\n";
                let _ = fs::write(judge_dir.join("Launch-Judge.bat"), bat_content);
                let _ = fs::write(judge_dir.join("WebView2Loader.dll"), WEBVIEW2_LOADER_X64);
            } else {
                let unix_judge_target = judge_dir.join("warm_judge_app");
                let _ = fs::write(&unix_judge_target, &judge_bytes);
                let sh_content = "#!/bin/sh\nDIR=\"$(cd \"$(dirname \"$0\")\" && pwd)\"\nexec \"$DIR/warm_judge_app\" \"$@\"\n";
                let _ = fs::write(judge_dir.join("Launch-Judge.sh"), sh_content);
            }
        }
    }

    let manifest = ContestManifest {
        contest: contest.clone(),
        policy: monitoring_policy.clone(),
        judge_public_key_hex: judge_keypair.public_key_hex(),
        manifest_signing_key_pub_hex: signing_keypair.public_key_hex(),
        client_binary_checksums: binary_checksums,
        created_at: Utc::now(),
        account_mode: account_config,
    };

    let signed_manifest = manifest.sign(&signing_keypair)?;

    let manifest_bytes = signed_manifest.manifest.canonical_bytes()?;
    let signed_manifest_bytes = serde_json::to_vec_pretty(&signed_manifest)
        .map_err(|e| WarmError::Serialization(e.to_string()))?;

    fs::write(manifests_dir.join("contest_manifest.json"), &manifest_bytes)
        .map_err(|e| WarmError::Io(e.to_string()))?;
    fs::write(
        manifests_dir.join("contest_manifest.json.sig"),
        &signed_manifest.signature_hex,
    )
    .map_err(|e| WarmError::Io(e.to_string()))?;
    let _ = fs::write(
        manifests_dir.join("contest_signed_manifest.json"),
        &signed_manifest_bytes,
    );

    let _ = fs::write(
        client_win_dir.join("contest_manifest.json"),
        &manifest_bytes,
    );
    let _ = fs::write(
        client_win_dir.join("contest_manifest.json.sig"),
        &signed_manifest.signature_hex,
    );
    let _ = fs::write(
        client_win_dir.join("contest_signed_manifest.json"),
        &signed_manifest_bytes,
    );

    let _ = fs::write(
        client_linux_dir.join("contest_manifest.json"),
        &manifest_bytes,
    );
    let _ = fs::write(
        client_linux_dir.join("contest_manifest.json.sig"),
        &signed_manifest.signature_hex,
    );
    let _ = fs::write(
        client_linux_dir.join("contest_signed_manifest.json"),
        &signed_manifest_bytes,
    );

    let _ = fs::write(
        client_macos_dir.join("contest_manifest.json"),
        &manifest_bytes,
    );
    let _ = fs::write(
        client_macos_dir.join("contest_manifest.json.sig"),
        &signed_manifest.signature_hex,
    );
    let _ = fs::write(
        client_macos_dir.join("contest_signed_manifest.json"),
        &signed_manifest_bytes,
    );

    let _ = fs::write(judge_dir.join("contest_manifest.json"), &manifest_bytes);
    let _ = fs::write(
        judge_dir.join("contest_manifest.json.sig"),
        &signed_manifest.signature_hex,
    );
    let _ = fs::write(
        judge_dir.join("contest_signed_manifest.json"),
        &signed_manifest_bytes,
    );

    let config_json = serde_json::to_string_pretty(&contest)
        .map_err(|e| WarmError::Serialization(e.to_string()))?;
    fs::write(config_dir.join("contest_config.json"), &config_json)
        .map_err(|e| WarmError::Io(e.to_string()))?;

    let policies_json = serde_json::to_string_pretty(&monitoring_policy)
        .map_err(|e| WarmError::Serialization(e.to_string()))?;
    fs::write(config_dir.join("policies.json"), &policies_json)
        .map_err(|e| WarmError::Io(e.to_string()))?;

    fs::write(
        config_dir.join("judge_evidence_key.pub"),
        judge_keypair.public_key_hex(),
    )
    .map_err(|e| WarmError::Io(e.to_string()))?;
    fs::write(
        config_dir.join("manifest_signing_key.pub"),
        signing_keypair.public_key_hex(),
    )
    .map_err(|e| WarmError::Io(e.to_string()))?;

    let client_win_cfg = client_win_dir.join("configuration");
    let _ = fs::create_dir_all(&client_win_cfg);
    let _ = fs::write(client_win_cfg.join("contest_config.json"), &config_json);
    let _ = fs::write(client_win_cfg.join("policies.json"), &policies_json);
    let _ = fs::write(
        client_win_cfg.join("judge_evidence_key.pub"),
        judge_keypair.public_key_hex(),
    );
    let _ = fs::write(
        client_win_cfg.join("manifest_signing_key.pub"),
        signing_keypair.public_key_hex(),
    );

    let judge_cfg = judge_dir.join("configuration");
    let _ = fs::create_dir_all(&judge_cfg);
    let _ = fs::write(judge_cfg.join("contest_config.json"), &config_json);
    let _ = fs::write(judge_cfg.join("policies.json"), &policies_json);
    let _ = fs::write(
        judge_cfg.join("judge_evidence_key.pub"),
        judge_keypair.public_key_hex(),
    );
    let _ = fs::write(
        judge_cfg.join("manifest_signing_key.pub"),
        signing_keypair.public_key_hex(),
    );

    let judge_priv_path = judge_keys_dir.join("judge_evidence_key.priv");
    fs::write(&judge_priv_path, judge_keypair.private_key_hex())
        .map_err(|e| WarmError::Io(e.to_string()))?;

    let signing_priv_path = judge_keys_dir.join("manifest_signing_key.priv");
    fs::write(&signing_priv_path, signing_keypair.private_key_hex())
        .map_err(|e| WarmError::Io(e.to_string()))?;

    let instructions = format!(
        r#"# Verification Instructions for {title}

**Contest Identifier:** `{id}`
**Contest UUID:** `{uuid}`
**Organizer:** {organizer}

---

## Cryptographic Key Fingerprints

- **Manifest Signing Public Key:** `{signing_pk}`
  - Fingerprint: `{signing_fp}`
- **Judge Decryption Public Key:** `{judge_pk}`
  - Fingerprint: `{judge_fp}`

---

## Authorized USB Export

To perform an authorized USB export, copy the file:
`judge/usb_token/warm_export_auth.token`
to the root of any USB drive. Inserting it into the participant's computer will automatically finalize and export the encrypted evidence log.

---

## Verifying Manifest Authenticity

Run the verification tool with the organizer's public key:

```bash
warm_judge_app verify-manifest \
  --manifest ./manifests/contest_manifest.json \
  --signature ./manifests/contest_manifest.json.sig \
  --public-key ./configuration/manifest_signing_key.pub
```
"#,
        title = contest.title,
        id = contest.id,
        uuid = contest.uuid,
        organizer = contest.organizer,
        signing_pk = signing_keypair.public_key_hex(),
        signing_fp = compute_fingerprint(signing_keypair.verifying_key.as_bytes()),
        judge_pk = judge_keypair.public_key_hex(),
        judge_fp = compute_fingerprint(judge_keypair.public_key.as_bytes()),
    );

    fs::write(
        contest_dir.join("VERIFICATION_INSTRUCTIONS.md"),
        &instructions,
    )
    .map_err(|e| WarmError::Io(e.to_string()))?;
    let _ = fs::write(
        client_win_dir.join("VERIFICATION_INSTRUCTIONS.md"),
        &instructions,
    );

    let checksum_content = format!(
        "{manifest_hash}  manifests/contest_manifest.json\n",
        manifest_hash = sha256_digest(&manifest_bytes),
    );
    let checksums_path = checksums_dir.join("SHA256SUMS.txt");
    fs::write(&checksums_path, checksum_content).map_err(|e| WarmError::Io(e.to_string()))?;

    Ok(ContestDistBundle {
        contest_id: contest.id,
        root_dir: contest_dir,
        signed_manifest,
        judge_private_key_path: judge_priv_path,
        manifest_signing_key_priv_path: signing_priv_path,
        checksums_path,
        participant_client_path: copied_participant_client,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_contest_distribution() {
        let temp_dir =
            std::env::temp_dir().join(format!("warm_dist_test_{}", uuid::Uuid::new_v4()));

        let config = ContestBuildConfig {
            title: "GOCUP 1".to_string(),
            organizer: "National Committee".to_string(),
            description: "Test Contest".to_string(),
            start_time: None,
            end_time: None,
            prohibited_apps: vec!["ollama.exe".to_string(), "lmstudio.exe".to_string()],
            restricted_domains: vec!["chatgpt.com".to_string(), "claude.ai".to_string()],
            supported_platforms: vec!["windows".to_string(), "linux".to_string()],
            branding_theme: "dark".to_string(),
            output_base_dir: temp_dir.clone(),
            enable_cpp_compiler: false,
            participation_mode: warm_core::ParticipationMode::NoAccounts,
            account_count: 0,
        };

        let bundle = generate_contest_distribution(&config).expect("Generation should succeed");
        assert_eq!(bundle.contest_id, "gocup-1");
        assert!(bundle.root_dir.exists());

        assert!(bundle
            .root_dir
            .join("manifests/contest_manifest.json")
            .exists());
        assert!(bundle
            .root_dir
            .join("manifests/contest_manifest.json.sig")
            .exists());
        assert!(bundle
            .root_dir
            .join("configuration/contest_config.json")
            .exists());
        assert!(bundle.root_dir.join("configuration/policies.json").exists());
        assert!(bundle
            .root_dir
            .join("configuration/judge_evidence_key.pub")
            .exists());
        assert!(bundle
            .root_dir
            .join("configuration/manifest_signing_key.pub")
            .exists());
        assert!(bundle.judge_private_key_path.exists());
        assert!(bundle.checksums_path.exists());
        assert!(bundle
            .root_dir
            .join("judge/usb_token/warm_export_auth.token")
            .exists());
        assert!(bundle
            .root_dir
            .join("VERIFICATION_INSTRUCTIONS.md")
            .exists());

        assert!(!bundle
            .root_dir
            .join("client/judge_evidence_key.priv")
            .exists());

        assert!(bundle.signed_manifest.verify().is_ok());

        let _ = fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn test_generate_contest_distribution_with_accounts() {
        let temp_dir =
            std::env::temp_dir().join(format!("warm_dist_acc_test_{}", uuid::Uuid::new_v4()));

        let config = ContestBuildConfig {
            title: "GOCUP Mode B".to_string(),
            organizer: "National Committee".to_string(),
            description: "Accounts Test Contest".to_string(),
            start_time: None,
            end_time: None,
            prohibited_apps: vec![],
            restricted_domains: vec![],
            supported_platforms: vec!["windows".to_string()],
            branding_theme: "dark".to_string(),
            output_base_dir: temp_dir.clone(),
            enable_cpp_compiler: false,
            participation_mode: warm_core::ParticipationMode::GeneratedAccounts,
            account_count: 5,
        };

        let bundle = generate_contest_distribution(&config).expect("Generation should succeed");
        assert!(bundle.signed_manifest.verify().is_ok());
        assert_eq!(
            bundle.signed_manifest.manifest.account_mode.mode,
            warm_core::ParticipationMode::GeneratedAccounts
        );
        assert_eq!(
            bundle.signed_manifest.manifest.account_mode.verifiers.len(),
            5
        );

        let judge_csv = bundle.root_dir.join("judge/credentials.csv");
        assert!(judge_csv.exists());
        let csv_content = fs::read_to_string(judge_csv).unwrap();
        assert!(csv_content.contains("GOCUP-MODE-B-001"));
        assert!(csv_content.contains("GOCUP-MODE-B-005"));

        let judge_pdf = bundle.root_dir.join("judge/credentials.pdf");
        assert!(judge_pdf.exists());
        let pdf_bytes = fs::read(judge_pdf).unwrap();
        assert!(pdf_bytes.starts_with(b"%PDF-1.4"));

        assert!(!bundle.root_dir.join("client/credentials.csv").exists());
        assert!(!bundle
            .root_dir
            .join("client/windows/credentials.csv")
            .exists());

        let _ = fs::remove_dir_all(temp_dir);
    }
}
