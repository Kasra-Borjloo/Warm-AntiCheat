# Warm-AntiCheat Windows Build & Packaging Script
param (
    [string]$Configuration = "release",
    [switch]$RunTests,
    [switch]$Clippy
)

$ErrorActionPreference = "Stop"

# Ensure space-free target directory on Windows if path contains spaces
if ($PWD.Path -match '\s' -and -not $env:CARGO_TARGET_DIR) {
    $env:CARGO_TARGET_DIR = "C:\warm_target"
    Write-Host "[*] Path contains spaces. Setting CARGO_TARGET_DIR=$env:CARGO_TARGET_DIR" -ForegroundColor DarkGray
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   Warm-AntiCheat Build Script (Windows)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Format check
Write-Host "[1/4] Running rustfmt..." -ForegroundColor Yellow
cargo fmt --all -- --check

# 2. Clippy check
if ($Clippy) {
    Write-Host "[2/4] Running clippy lints..." -ForegroundColor Yellow
    cargo clippy --workspace --all-targets -- -D warnings
} else {
    Write-Host "[2/4] Skipping clippy (use -Clippy to enable)" -ForegroundColor DarkGray
}

# 3. Test execution
if ($RunTests) {
    Write-Host "[3/4] Running all automated tests..." -ForegroundColor Yellow
    cargo test --workspace
} else {
    Write-Host "[3/4] Skipping tests (use -RunTests to enable)" -ForegroundColor DarkGray
}

# 4. Build applications
Write-Host "[4/4] Building release binaries..." -ForegroundColor Yellow
if ($Configuration -eq "release") {
    cargo build --workspace --release
} else {
    cargo build --workspace
}

Write-Host "`n[SUCCESS] Build completed successfully!" -ForegroundColor Green
Write-Host "Executables located in target/$Configuration/" -ForegroundColor Green
