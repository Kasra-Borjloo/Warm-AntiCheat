# Warm-AntiCheat Architecture

## 1. System Philosophy & Decoupled Design

Warm-AntiCheat is designed with three core architectural mandates:
1. **Zero Phone-Home Dependency**: Competitions frequently operate in isolated local networks, stadiums, or air-gapped auditoriums without stable cloud connectivity. All evidence recording, sealing, and analysis must function completely offline.
2. **Cryptographic Asymmetry**: Participants are assumed to possess administrative privileges over their devices. The architecture guarantees that no participant can forge manifests, inspect judge notes, or decrypt other competitors' submissions, because private keys are strictly retained by organizers.
3. **Evidence-Based Forensics**: The system never operates as an opaque, arbitrary ban engine. Instead, it generates an immutable, verifiable ledger of timestamped system events. Judges receive transparent, explainable timelines with full cryptographic provenance.

```mermaid
flowchart TD
    subgraph BuilderApp["Contest Builder (Organizer)"]
        CB_Config["Contest Configuration\n(Title, UUID, Policies)"]
        CB_Keys["Key Generator\n(Ed25519 Signing + X25519 Encryption)"]
        CB_Manifest["Manifest Signer\n(SHA-256 Checksums + Sig)"]
        CB_Dist["Dist Generator\n(dist/CONTEST-ID/...)"]
    end

    subgraph ParticipantApp["Participant Client (Student / Competitor)"]
        PC_Enroll["Enrollment & Token Validation"]
        PC_Collector["Event Collectors\n(Process, Browser, Network, Lifecycle)"]
        PC_Chain["Tamper-Evident Hash Chain\n(SHA-256 + Sequence Tracker)"]
        PC_Store["Encrypted Storage Engine\n(AES-256-GCM + Ephemeral X25519)"]
        PC_Export["USB Evidence Exporter"]
    end

    subgraph JudgeApp["Judge Verifier (Competition Jury)"]
        JV_Import["USB Evidence Importer"]
        JV_Auth["Manifest & Signature Verification"]
        JV_Decrypt["Decryption Engine\n(Judge Private X25519)"]
        JV_Audit["Deterministic Forensics\n(Timeline & Rule Correlator)"]
        JV_AI["Optional Offline AI Summarizer"]
        JV_UI["Judge Dashboard\n(SAFE / UNSAFE / REVIEW REQUIRED)"]
    end

    CB_Config --> CB_Keys --> CB_Manifest --> CB_Dist
    CB_Dist -->|"Public Keys & Manifest"| PC_Enroll
    CB_Dist -->|"Private Decryption Key"| JV_Decrypt

    PC_Enroll --> PC_Collector --> PC_Chain --> PC_Store --> PC_Export
    PC_Export -->|"Encrypted Evidence via USB"| JV_Import
    JV_Import --> JV_Auth --> JV_Decrypt --> JV_Audit --> JV_UI
    JV_Audit -.-> JV_AI -.-> JV_UI
```

---

## 2. Monorepo Crate Architecture

The repository is structured as a Cargo workspace with distinct concerns:

| Crate / App | Purpose | Dependencies |
| :--- | :--- | :--- |
| `crates/core` | Core models: Contest, Participant, Session, Enrollment Tokens | serde, uuid, chrono, thiserror |
| `crates/crypto` | X25519, Ed25519, AES-256-GCM, HKDF, SHA-256, Hash Chains | dalek suites, sha2, aes-gcm |
| `crates/events` | Strongly typed audit events & JSON schema | core, serde, uuid, chrono |
| `crates/storage` | SQLite event store, sequence integrity & encrypted archive packaging | rusqlite, crypto, events |
| `crates/policies` | Security policies: prohibited process rules, restricted browser domains | core, serde |
| `crates/platform` | OS-specific collectors (Windows Win32, Linux /proc, macOS ES abstraction) | sysinfo, events, policies |
| `crates/verifier` | Forensic classifier (SAFE, UNSAFE, REVIEW REQUIRED) | crypto, events, policies, storage |
| `crates/audit` | Timeline analysis, event correlation & local LLM summarization | events, verifier |
| `crates/builder_core` | Build distributor, manifest packager & checksum validator | core, crypto, policies |
| `apps/builder` | Contest Builder desktop application UI and orchestration | builder_core, core, crypto |
| `apps/participant` | Participant Client desktop application UI, monitoring daemon | platform, storage, policies |
| `apps/judge` | Judge Verifier desktop application UI, dashboard & report reviewer | verifier, audit, storage |

---

## 3. Data Flow & Cryptographic Lifecycle

### Stage 1: Contest Generation (Contest Builder)
1. Organizer defines contest parameters: `title`, `contest_id`, `start_time`, `end_time`, `restricted_domains`, `prohibited_apps`.
2. Builder generates:
   - **Manifest Signing Key Pair** (Ed25519): `manifest_signing_key.priv` (kept by organizer) and `manifest_signing_key.pub` (embedded in client).
   - **Evidence Encryption Key Pair** (X25519): `judge_evidence_key.priv` (stored in Judge package only) and `judge_evidence_key.pub` (embedded in client).
3. Builder outputs the standardized `dist/<CONTEST_ID>/` bundle.

### Stage 2: Competition Session (Participant Client)
1. Participant launches the client and enrolls with their assigned Participant ID and Session Token.
2. The client initializes an append-only SQLite storage database.
3. Event collectors monitor:
   - Process creations, terminations, and prohibited AI runtimes (e.g., Ollama, LM Studio, llama.cpp).
   - Restricted domain web access attempts.
   - Network interface transitions (Wi-Fi SSID, Ethernet connects/disconnects).
   - System lifecycle events (sleep, wake, application shutdowns).
4. Each event is recorded into a SHA-256 hash chain:
   $$\text{Hash}_n = \text{SHA-256}(\text{Seq}_n \parallel \text{Timestamp}_n \parallel \text{Hash}_{n-1} \parallel \text{Category}_n \parallel \text{Payload}_n)$$
5. The event payload is sealed into the encrypted SQLite database using AES-256-GCM.

### Stage 3: Offline Evidence Hand-off (Removable USB / Storage)
1. At the conclusion of the contest, or upon proctor request, the Participant Client exports the encrypted audit archive.
2. The archive includes the participant ID, contest UUID, sequence manifest, encrypted event database, and file integrity checksums.
3. The package is transferred to an authorized Judge workstation.

### Stage 4: Verification & Forensic Analysis (Judge Verifier)
1. Judge selects the contest and provides the Judge Private Key (`judge_evidence_key.priv`).
2. The Verifier verifies:
   - Manifest digital signature against the organizer's public key.
   - Evidence package file hashes and checksum integrity.
   - Continuous hash-chain sequence from `Seq 0` to final event.
3. The Verifier decrypts the audit events and executes deterministic correlation rules:
   - **`SAFE`**: No prohibited processes, domain violations, or broken monitoring periods observed.
   - **`UNSAFE`**: Direct, verifiable evidence of a prohibited tool or domain access during the active contest window.
   - **`REVIEW REQUIRED`**: Missing sequence numbers, unexplained monitoring gaps, or corrupted event chains.
4. An optional local AI summarizer produces human-readable executive summaries highlighting pertinent timestamps for jury review.
