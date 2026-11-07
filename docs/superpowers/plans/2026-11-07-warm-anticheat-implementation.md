# Warm-AntiCheat Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Design, implement, test, document, and release Warm-AntiCheat, an offline-first, production-oriented, open-source, cross-platform anti-cheat and competition integrity framework with Contest Builder, Participant Client, and Judge Verifier.

**Architecture:** A modular Rust workspace containing three Tauri/Rust desktop applications (`apps/builder`, `apps/participant`, `apps/judge`) sharing clean, decoupled domain crates (`crates/core`, `crates/crypto`, `crates/events`, `crates/storage`, `crates/policies`, `crates/platform`, `crates/verifier`, `crates/audit`). The architecture uses strictly offline cryptographic verification (Ed25519 manifests, X25519/AES-256-GCM encrypted audit logs, SHA-256 event hash-chains), platform event collectors, deterministic rule verification, and clean USB evidence export.

**Tech Stack:** Rust 2021, Tauri 2.0, Tokio, SQLite (rusqlite/bundled), X25519-dalek, Ed25519-dalek, AES-GCM, HKDF, SHA2, Serde, HTML5/CSS/TypeScript for UI.

**Spec:** Autonomous Instructions for Warm-AntiCheat by Kasra Borjloo.

## Global Constraints
- Target Platforms: Windows (x86_64, aarch64), Linux (x86_64, aarch64), macOS (x86_64, aarch64).
- Offline-first: zero network phone-home dependency for competition integrity; operates in disconnected environments.
- Non-repudiation & Cryptography: Standard algorithms only (X25519, Ed25519, AES-256-GCM, SHA-256). Private decryption keys never placed in participant clients.
- Classification categories: SAFE, UNSAFE, REVIEW REQUIRED with clear supporting event evidence.
- Commit identity: Kasra Borjloo <kasraborjloo2009@gmail.com>.
- UI Language: English only, modern dark/light themes.

---

### Task 1: Milestone 1 — Repository Initialization & Architectural Documentation
**Files:**
- Create: `Cargo.toml` (root workspace)
- Create: `rustfmt.toml`
- Create: `.gitignore`
- Create: `README.md`
- Create: `ARCHITECTURE.md`
- Create: `SECURITY.md`
- Create: `THREAT_MODEL.md`
- Create: `CONTRIBUTING.md`
- Create: `BUILDING.md`
- Create: `CRYPTOGRAPHY.md`
- Create: `PRIVACY.md`
- Create: `RELEASE_VERIFICATION.md`
- Create: `BUILDER_GUIDE.md`
- Create: `PARTICIPANT_GUIDE.md`
- Create: `JUDGE_GUIDE.md`

### Task 2: Milestone 2 — Shared Core Library (`crates/core`)
**Files:**
- Create: `crates/core/Cargo.toml`
- Create: `crates/core/src/lib.rs`
- Create: `crates/core/src/contest.rs`
- Create: `crates/core/src/participant.rs`
- Create: `crates/core/src/session.rs`
- Create: `crates/core/src/token.rs`
- Create: `crates/core/src/error.rs`
- Create: `crates/core/tests/test_core.rs`

### Task 3: Milestone 3 — Cryptography Engine (`crates/crypto`)
**Files:**
- Create: `crates/crypto/Cargo.toml`
- Create: `crates/crypto/src/lib.rs`
- Create: `crates/crypto/src/asymmetric.rs` (X25519, Ed25519)
- Create: `crates/crypto/src/symmetric.rs` (AES-256-GCM, HKDF)
- Create: `crates/crypto/src/hash.rs` (SHA-256, hash chain)
- Create: `crates/crypto/src/fingerprint.rs`
- Create: `crates/crypto/tests/test_crypto.rs`

### Task 4: Milestone 4 — Event Schemas & Encrypted Storage (`crates/events` & `crates/storage`)
**Files:**
- Create: `crates/events/Cargo.toml`
- Create: `crates/events/src/lib.rs`
- Create: `crates/events/src/model.rs`
- Create: `crates/events/src/category.rs`
- Create: `crates/storage/Cargo.toml`
- Create: `crates/storage/src/lib.rs`
- Create: `crates/storage/src/chain.rs`
- Create: `crates/storage/src/sqlite.rs`
- Create: `crates/storage/src/export.rs`
- Create: `crates/storage/tests/test_storage.rs`

### Task 5: Milestone 5 & 6 — Contest Builder & Manifest Pipeline (`crates/builder_core`, `apps/builder`)
**Files:**
- Create: `crates/builder_core/Cargo.toml`
- Create: `crates/builder_core/src/lib.rs`
- Create: `crates/builder_core/src/manifest.rs`
- Create: `crates/builder_core/src/generator.rs`
- Create: `apps/builder/Cargo.toml`
- Create: `apps/builder/src/main.rs`
- Create: `apps/builder/ui/index.html`
- Create: `apps/builder/ui/style.css`
- Create: `apps/builder/ui/app.js`

### Task 6: Milestone 7, 8, 9, 10, 11 — Monitoring Collectors & Participant Client (`crates/platform`, `crates/policies`, `apps/participant`)
**Files:**
- Create: `crates/platform/Cargo.toml`
- Create: `crates/platform/src/lib.rs`
- Create: `crates/platform/src/process.rs` (Windows toolhelp/Win32 & cross-platform simulation)
- Create: `crates/platform/src/network.rs` (interface/adapter tracking)
- Create: `crates/platform/src/lifecycle.rs` (sleep/wake/interruption tracking)
- Create: `crates/policies/Cargo.toml`
- Create: `crates/policies/src/lib.rs`
- Create: `crates/policies/src/browser.rs`
- Create: `crates/policies/src/apps.rs`
- Create: `apps/participant/Cargo.toml`
- Create: `apps/participant/src/main.rs`
- Create: `apps/participant/ui/index.html`
- Create: `apps/participant/ui/style.css`
- Create: `apps/participant/ui/app.js`

### Task 7: Milestone 12, 13, 14, 15, 16 — Verification, Audit, USB Export & Judge Verifier (`crates/verifier`, `crates/audit`, `apps/judge`)
**Files:**
- Create: `crates/verifier/Cargo.toml`
- Create: `crates/verifier/src/lib.rs`
- Create: `crates/verifier/src/classifier.rs` (SAFE, UNSAFE, REVIEW REQUIRED)
- Create: `crates/audit/Cargo.toml`
- Create: `crates/audit/src/lib.rs`
- Create: `crates/audit/src/deterministic.rs`
- Create: `crates/audit/src/ai_summarizer.rs`
- Create: `apps/judge/Cargo.toml`
- Create: `apps/judge/src/main.rs`
- Create: `apps/judge/ui/index.html`
- Create: `apps/judge/ui/style.css`
- Create: `apps/judge/ui/app.js`

### Task 8: Milestone 17, 18, 19, 20 — Packaging, CI/CD, Tests & Release Verification
**Files:**
- Create: `.github/workflows/ci.yml`
- Create: `.github/workflows/release.yml`
- Create: `tests/integration_test.rs`
- Create: `scripts/build.ps1`
- Create: `scripts/build.sh`
- Create: `examples/gocup-1-sample/`
