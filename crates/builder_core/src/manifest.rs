use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use warm_core::{Contest, Result, WarmError};
use warm_crypto::{verify_signature_hex, ManifestSigningKeypair};
use warm_policies::MonitoringPolicy;

/// Canonical unsigned contest manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContestManifest {
    pub contest: Contest,
    pub policy: MonitoringPolicy,
    pub judge_public_key_hex: String,
    pub manifest_signing_key_pub_hex: String,
    pub client_binary_checksums: BTreeMap<String, String>,
    pub created_at: DateTime<Utc>,
}

impl ContestManifest {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|e| WarmError::Serialization(format!("Manifest serialization error: {e}")))
    }

    /// Cryptographically signs this manifest using the Organizer's Ed25519 signing keypair.
    pub fn sign(&self, keypair: &ManifestSigningKeypair) -> Result<SignedContestManifest> {
        let bytes = self.canonical_bytes()?;
        let signature_hex = keypair.sign_hex(&bytes);
        Ok(SignedContestManifest {
            manifest: self.clone(),
            signature_hex,
        })
    }
}

/// Official signed contest manifest distributed to judges and participants.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedContestManifest {
    pub manifest: ContestManifest,
    pub signature_hex: String,
}

impl SignedContestManifest {
    /// Verify the Ed25519 digital signature of the manifest using its declared signing key.
    pub fn verify(&self) -> Result<()> {
        let bytes = self.manifest.canonical_bytes()?;
        verify_signature_hex(
            &self.manifest.manifest_signing_key_pub_hex,
            &bytes,
            &self.signature_hex,
        )
    }

    /// Verify signature with an explicit external public key.
    pub fn verify_with_key(&self, expected_public_key_hex: &str) -> Result<()> {
        let bytes = self.manifest.canonical_bytes()?;
        verify_signature_hex(expected_public_key_hex, &bytes, &self.signature_hex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use std::collections::BTreeMap;

    #[test]
    fn test_manifest_signing_and_verification() {
        let start = Utc::now();
        let end = start + Duration::hours(5);
        let contest = Contest::new("GOCUP 1", "Org", "Desc", start, end).unwrap();

        let signing_keypair = ManifestSigningKeypair::generate();
        let mut checksums = BTreeMap::new();
        checksums.insert("windows-x86_64".to_string(), "sha256_mock_win".to_string());

        let manifest = ContestManifest {
            contest,
            policy: MonitoringPolicy::default(),
            judge_public_key_hex: "dummy_judge_pk_hex".to_string(),
            manifest_signing_key_pub_hex: signing_keypair.public_key_hex(),
            client_binary_checksums: checksums,
            created_at: Utc::now(),
        };

        let signed = manifest.sign(&signing_keypair).unwrap();
        assert!(signed.verify().is_ok());

        // Altering title breaks signature
        let mut tampered = signed.clone();
        tampered.manifest.contest.title = "GOCUP 2".to_string();
        assert!(tampered.verify().is_err());
    }
}
