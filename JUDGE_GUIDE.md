# Judge Verifier User Guide

The **Judge Verifier** (`apps/judge`) is used exclusively by competition jury members and proctors to inspect, decrypt, validate, and audit evidence packages collected from participants.

---

## 1. Setting Up the Judge Environment

1. Launch `warm_judge_app` on the trusted judge machine.
2. Load the contest manifest:
   - Select `dist/<CONTEST_ID>/manifests/contest_manifest.json`.
3. Provide the Organizer Private Decryption Key:
   - Select `dist/<CONTEST_ID>/judge/keys/judge_evidence_key.priv`.

---

## 2. Importing Evidence Packages

Evidence can be imported in two ways:
- **Direct USB Scan**: Connect the judge USB drive. The application scans for participant evidence archives automatically.
- **Manual Import**: Click **"Import Evidence Archive"** and select a `.warm-evidence` package or folder.

---

## 3. Automated Forensic Verification

Upon import, the Verifier executes:
1. **Digital Signature Check**: Verifies that the manifest is signed with the contest's Ed25519 organizer key.
2. **File Checksums**: Validates SHA-256 digests of all imported database and sequence files.
3. **Hash Chain Continuity**: Verifies every sequential link from $H_0$ (genesis) to $H_N$. Flags broken chains or missing sequence IDs.
4. **Decryption**: Decrypts AES-256-GCM event payloads using the judge private key.
5. **Deterministic Policy Matcher**: Correlates events against contest policies (prohibited apps, restricted domains, monitoring gaps).

---

## 4. Interpreting Verdicts

The Judge Verifier classifies each participant session into one of three statuses:

### 🟢 SAFE
- No prohibited application was executed during the active contest window.
- No restricted domain navigation was detected.
- Hash-chain integrity verified without gaps.
- Monitoring heartbeats remained continuous within allowed policy thresholds.

### 🔴 UNSAFE
- Verifiable, authentic evidence of prohibited activity was recorded (e.g., `ollama` running during the contest window).
- Specific timestamps, process IDs, and policy rule violations are displayed with direct evidence citations.

### 🟡 REVIEW REQUIRED
- A monitoring interruption occurred (e.g., process killed and restarted with an unexplained time gap).
- Tampered or corrupted hash chain detected.
- Submission from an unverified or unsigned client binary.
- Requires jury investigation and proctor inquiry.
