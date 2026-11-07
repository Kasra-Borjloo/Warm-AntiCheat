# Building Warm-AntiCheat

This guide explains how to compile, test, and package Warm-AntiCheat across supported operating systems.

---

## Supported Platforms & Architectures

| OS | Target Architecture | Binary / Package Format |
| :--- | :--- | :--- |
| **Windows** | `x86_64-pc-windows-msvc` / `gnu`, `aarch64-pc-windows-msvc` | EXE, MSI Installer |
| **Linux** | `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu` | Binary, AppImage, DEB, RPM |
| **macOS** | `x86_64-apple-darwin`, `aarch64-apple-darwin` | Universal Binary / DMG |

---

## 1. System Requirements

- **Rust Toolchain**: 1.80 or later (`rustup default stable`)
- **C/C++ Build Toolchain**:
  - Windows: MSVC C++ Build Tools or MinGW-w64 (via `stable-x86_64-pc-windows-gnu`)
  - Linux: `gcc`, `pkg-config`, `libssl-dev`, `libsqlite3-dev`
  - macOS: Xcode Command Line Tools
- **Node.js**: v20+ LTS and `npm`

---

## 2. Fast Build & Workspace Verification

Clone the repository and build all crates:

```bash
# Check formatting
cargo fmt --all -- --check

# Check workspace compilation
cargo check --workspace

# Run complete automated test suite
cargo test --workspace

# Build release binaries
cargo build --workspace --release
```

---

## 3. Building Desktop Applications

The project provides three applications located in `apps/`:
1. `apps/builder`: Contest Builder
2. `apps/participant`: Participant Client
3. `apps/judge`: Judge Verifier

```bash
# Build specific desktop app
cargo build -p warm_builder_app --release
cargo build -p warm_participant_app --release
cargo build -p warm_judge_app --release
```

Release binaries are produced under `target/release/`.
