use crate::manifest::{ContestManifest, SignedContestManifest};
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

/// High-level builder configuration passed by organizer UI / CLI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContestBuildConfig {
    pub title: String,
    pub organizer: String,
    pub description: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub prohibited_apps: Vec<String>,
    pub restricted_domains: Vec<String>,
    pub supported_platforms: Vec<String>,
    pub branding_theme: String,
    pub output_base_dir: PathBuf,
}

/// Result returned after successful contest distribution package generation.
#[derive(Debug, Clone)]
pub struct ContestDistBundle {
    pub contest_id: String,
    pub root_dir: PathBuf,
    pub signed_manifest: SignedContestManifest,
    pub judge_private_key_path: PathBuf,
    pub manifest_signing_key_priv_path: PathBuf,
    pub checksums_path: PathBuf,
}

/// Generates the complete, standardized contest distribution output.
pub fn generate_contest_distribution(config: &ContestBuildConfig) -> Result<ContestDistBundle> {
    let contest = Contest::new(
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
    let manifests_dir = contest_dir.join("manifests");
    let config_dir = contest_dir.join("configuration");
    let checksums_dir = contest_dir.join("checksums");

    // Create directory hierarchy
    for d in [
        &contest_dir,
        &client_dir,
        &client_win_dir,
        &client_linux_dir,
        &client_macos_dir,
        &judge_dir,
        &judge_keys_dir,
        &manifests_dir,
        &config_dir,
        &checksums_dir,
    ] {
        fs::create_dir_all(d).map_err(|e| {
            WarmError::Io(format!("Failed to create directory {}: {e}", d.display()))
        })?;
    }

    // 1. Generate contest cryptographic keypairs
    let signing_keypair = ManifestSigningKeypair::generate();
    let judge_keypair = EvidenceEncryptionKeypair::generate();

    // 2. Build policies
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
    };

    // 3. Create manifest and sign with organizer private key
    let mut binary_checksums = BTreeMap::new();
    binary_checksums.insert("windows-x86_64".to_string(), "PENDING_BUILD".to_string());
    binary_checksums.insert("linux-x86_64".to_string(), "PENDING_BUILD".to_string());
    binary_checksums.insert("macos-universal".to_string(), "PENDING_BUILD".to_string());

    let manifest = ContestManifest {
        contest: contest.clone(),
        policy: monitoring_policy.clone(),
        judge_public_key_hex: judge_keypair.public_key_hex(),
        manifest_signing_key_pub_hex: signing_keypair.public_key_hex(),
        client_binary_checksums: binary_checksums,
        created_at: Utc::now(),
    };

    let signed_manifest = manifest.sign(&signing_keypair)?;

    // 4. Write manifest files
    let manifest_json = serde_json::to_string_pretty(&signed_manifest.manifest)
        .map_err(|e| WarmError::Serialization(e.to_string()))?;
    fs::write(manifests_dir.join("contest_manifest.json"), &manifest_json)
        .map_err(|e| WarmError::Io(e.to_string()))?;
    fs::write(
        manifests_dir.join("contest_manifest.json.sig"),
        &signed_manifest.signature_hex,
    )
    .map_err(|e| WarmError::Io(e.to_string()))?;

    // 5. Write configuration files
    let config_json = serde_json::to_string_pretty(&contest)
        .map_err(|e| WarmError::Serialization(e.to_string()))?;
    fs::write(config_dir.join("contest_config.json"), config_json)
        .map_err(|e| WarmError::Io(e.to_string()))?;

    let policies_json = serde_json::to_string_pretty(&monitoring_policy)
        .map_err(|e| WarmError::Serialization(e.to_string()))?;
    fs::write(config_dir.join("policies.json"), policies_json)
        .map_err(|e| WarmError::Io(e.to_string()))?;

    // 6. Write Public keys to configuration/ (distributable with participant client)
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

    // 7. Write Private Keys to judge/keys/ ONLY (STRICT INVARIANT: NEVER PLACE IN CLIENT)
    let judge_priv_path = judge_keys_dir.join("judge_evidence_key.priv");
    fs::write(&judge_priv_path, judge_keypair.private_key_hex())
        .map_err(|e| WarmError::Io(e.to_string()))?;

    let signing_priv_path = judge_keys_dir.join("manifest_signing_key.priv");
    fs::write(&signing_priv_path, signing_keypair.private_key_hex())
        .map_err(|e| WarmError::Io(e.to_string()))?;

    // 8. Generate Verification Instructions
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
        instructions,
    )
    .map_err(|e| WarmError::Io(e.to_string()))?;

    // 9. Generate Checksums
    let checksum_content = format!(
        "{manifest_hash}  manifests/contest_manifest.json\n",
        manifest_hash = sha256_digest(manifest_json.as_bytes()),
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_generate_contest_distribution() {
        let temp_dir =
            std::env::temp_dir().join(format!("warm_dist_test_{}", uuid::Uuid::new_v4()));
        let start = Utc::now();
        let end = start + Duration::hours(4);

        let config = ContestBuildConfig {
            title: "GOCUP 1".to_string(),
            organizer: "National Committee".to_string(),
            description: "Test Contest".to_string(),
            start_time: start,
            end_time: end,
            prohibited_apps: vec!["ollama.exe".to_string(), "lmstudio.exe".to_string()],
            restricted_domains: vec!["chatgpt.com".to_string(), "claude.ai".to_string()],
            supported_platforms: vec!["windows".to_string(), "linux".to_string()],
            branding_theme: "dark".to_string(),
            output_base_dir: temp_dir.clone(),
        };

        let bundle = generate_contest_distribution(&config).expect("Generation should succeed");
        assert_eq!(bundle.contest_id, "gocup-1");
        assert!(bundle.root_dir.exists());

        // Verify structure
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
            .join("VERIFICATION_INSTRUCTIONS.md")
            .exists());

        // Ensure private key is NOT in client directory
        assert!(!bundle
            .root_dir
            .join("client/judge_evidence_key.priv")
            .exists());

        // Verify signed manifest
        assert!(bundle.signed_manifest.verify().is_ok());

        // Cleanup
        let _ = fs::remove_dir_all(temp_dir);
    }
}
