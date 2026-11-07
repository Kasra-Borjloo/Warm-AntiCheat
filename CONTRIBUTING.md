# Contributing to Warm-AntiCheat

Thank you for your interest in contributing to **Warm-AntiCheat**! We welcome contributions that uphold competition integrity, enhance cross-platform forensic capabilities, and improve cryptographic rigor.

---

## Code of Conduct & Principles

1. **Evidence-Based & Transparent**: All detection rules and classifiers must produce verifiable, explainable findings. Avoid heuristics that produce silent false positives.
2. **Offline-First**: Code must never introduce mandatory phone-home network calls. All cryptographic verification must be self-contained.
3. **Cryptographic Integrity**: Never introduce custom cryptographic ciphers or bypass established standards (X25519, Ed25519, AES-256-GCM, SHA-256).
4. **Platform Neutrality**: Keep core forensic logic independent of platform-specific collectors. Platform code in `crates/platform` must degrade gracefully when specific OS APIs or permissions are unavailable.

---

## Development Workflow

### Prerequisites
- Rust 2021 edition (Rust 1.80+ recommended)
- Cargo & Clippy (`rustup component add clippy rustfmt`)
- Node.js LTS (v20+) & npm

### Verification Commands
Before submitting pull requests, run:
```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

### Commit Guidelines
All commits should follow Conventional Commits:
- `feat(scope): description`
- `fix(scope): description`
- `test(scope): description`
- `docs(scope): description`
- `refactor(scope): description`
- `ci(scope): description`

All commits must use valid author information associated with your GitHub account.
