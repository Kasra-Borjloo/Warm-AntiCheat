# Contest Builder User Guide

The **Contest Builder** (`apps/builder`) enables organizers to configure, brand, and package contest-specific anti-cheat releases.

---

## 1. Launching the Builder

Run the Builder executable:
```bash
cargo run -p warm_builder_app --release
```

---

## 2. Contest Configuration Parameters

When creating a new contest, the Builder will prompt for:

1. **Contest Title**: Display name shown on all participant applications (e.g., `GOCUP 1`).
2. **Contest Identifier**: Slug used for directories and filenames (e.g., `gocup-1`).
3. **Contest UUID**: Automatically generated RFC 4122 v4 UUID uniquely identifying the contest.
4. **Organizer Name**: Sponsoring institution or individual (e.g., `Codeforces / ICPC Regional`).
5. **Start & End Time**: Competition time bounds (in UTC or local timezone).
6. **Security Policies**:
   - **Prohibited Applications**: Executable names such as `ollama.exe`, `ollama`, `lmstudio.exe`, `llama-cli`.
   - **Restricted Domains**: Domains such as `chatgpt.com`, `claude.ai`, `gemini.google.com`, `stackoverflow.com`.
   - **Event Retention Window**: Number of days audit evidence is maintained (e.g., 30 days).
7. **Branding & Theme**:
   - Optional contest logo and application icon.
   - Light or Dark theme preference.

---

## 3. Builder Output Structure

Upon clicking **"Generate Contest Package"**, the Builder generates:

```text
dist/
└── GOCUP-1/
    ├── client/
    │   ├── windows/          # Participant Client for Windows (.exe / .msi)
    │   ├── linux/            # Participant Client for Linux (.AppImage / .deb)
    │   └── macos/            # Participant Client for macOS (.dmg)
    ├── judge/
    │   ├── judge_verifier    # Judge Verifier executable
    │   └── keys/
    │       └── judge_evidence_key.priv  # CONFIDENTIAL: Private Decryption Key
    ├── manifests/
    │   ├── contest_manifest.json        # Canonical contest definition
    │   └── contest_manifest.json.sig    # Ed25519 digital signature
    ├── configuration/
    │   ├── contest_config.json          # Public configuration (contains public keys)
    │   └── policies.json               # Monitored rules & restricted domains
    ├── checksums/
    │   └── SHA256SUMS.txt               # Integrity checksums of all binaries
    └── VERIFICATION_INSTRUCTIONS.md     # How to verify package signatures
```

> **Security Warning**: Protect the `judge/keys/judge_evidence_key.priv` file. Never upload or distribute this file to participants. Only the official jury should possess this key.
