# Warm-AntiCheat

> **Production-Oriented, Open-Source, Cross-Platform Anti-Cheat & Competition Integrity Framework**

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-brightgreen.svg)]()
[![Language: Rust](https://img.shields.io/badge/Language-Rust%202021-orange.svg)]()
[![UI: Tauri](https://img.shields.io/badge/UI-Tauri%202.0-blueviolet.svg)]()

Warm-AntiCheat is an offline-first competition integrity and anti-cheat framework designed for in-person and distributed programming contests, hackathons, and algorithmic competitions.

Unlike invasive kernel-level drivers or cloud-dependent DRM systems, Warm-AntiCheat is designed specifically for **Bring-Your-Own-Device (BYOD)** academic and competitive programming environments. It establishes verifiable audit trails through tamper-evident hash-chained event logs, strong asymmetric cryptography (Ed25519 & X25519), and deterministic judge verification.

---

## Architecture Overview

Warm-AntiCheat is composed of three primary applications built on top of a modular Rust domain foundation:

```
Warm-AntiCheat/
├── apps/
│   ├── builder/        # Contest Builder (Organizers configure & package custom contests)
│   ├── participant/    # Participant Client (Monitors system, browser & network events locally)
│   └── judge/          # Judge Verifier (Decrypts & audits evidence packages offline)
├── crates/
│   ├── core/           # Contest models, participant identifiers, session state machine
│   ├── crypto/         # X25519, Ed25519, AES-256-GCM, HKDF, SHA-256 hash chains
│   ├── events/         # Strongly-typed competition audit events & schema
│   ├── storage/        # Encrypted SQLite storage, sequence trackers & USB export
│   ├── policies/       # Restricted domains, prohibited application definitions
│   ├── platform/       # Windows, Linux, and macOS process & lifecycle collectors
│   ├── compiler/       # Built-in offline C++23 compiler engine & isolated runner
│   ├── verifier/       # Policy evaluation & evidence classification (SAFE / UNSAFE / REVIEW REQUIRED)
│   ├── audit/          # Deterministic timeline correlation & optional offline AI summarizer
│   └── builder_core/   # Output dist packager & manifest signing engine
```

1. **Contest Builder (`apps/builder`)**: Used by competition organizers before the contest to generate customized, branded, and cryptographically signed participant and judge packages (e.g. for "GOCUP 1").
2. **Participant Client (`apps/participant`)**: Distributed to contestants. Runs locally with transparent disclosure, continuously recording process executions, restricted domain navigations, and network state into an encrypted, tamper-evident hash chain.
3. **Judge Verifier (`apps/judge`)**: Used by authorized judges. Receives encrypted evidence packages (via USB drive or local transfer), validates digital signatures and hash chains, decrypts event timelines, and produces explainable forensic verdicts.

---

## Key Security Principles

- **Offline-First**: Operates seamlessly without an external network server or Internet connection.
- **Asymmetric Cryptography**:
  - Participant clients possess **only** the organizer's public encryption key and public manifest signing key.
  - Private decryption keys remain exclusively in judge hands.
  - Signed manifests guarantee binary and policy integrity.
- **Tamper-Evident Hash Chains**: Every recorded event contains a sequence number, timestamp, previous event hash, and SHA-256 payload hash. Any deletion or truncation is detected immediately.
- **Explainable Findings**: Decisions are classified into **`SAFE`**, **`UNSAFE`**, and **`REVIEW REQUIRED`**, backed by concrete event references and timeline forensics.
- **Transparent Privacy**: Complete disclosure to participants regarding monitored metrics (processes, network interface changes, and declared restricted domains). No silent personal history scraping.

---

## Documentation Index

- [Architecture & Subsystems](ARCHITECTURE.md)
- [Threat Model & BYOD Analysis](THREAT_MODEL.md)
- [Security Architecture & Guarantees](SECURITY.md)
- [Cryptographic Specification](CRYPTOGRAPHY.md)
- [Privacy Notice & Retention Disclosure](PRIVACY.md)
- [Building & Toolchain Setup](BUILDING.md)
- [Built-in Offline C++ Compiler Guide](COMPILER_GUIDE.md)
- [Antivirus Compatibility & False-Positive Prevention](ANTIVIRUS_COMPATIBILITY.md)
- [Release Verification & Code Signing](RELEASE_VERIFICATION.md)
- [Contest Builder User Guide](BUILDER_GUIDE.md)
- [Participant Client User Guide](PARTICIPANT_GUIDE.md)
- [Judge Verifier User Guide](JUDGE_GUIDE.md)
- [Contributing Guidelines](CONTRIBUTING.md)

---

## License

Warm-AntiCheat is licensed under the **GNU General Public License v3.0 (GPL-3.0)**. See [LICENSE](LICENSE) for details.
