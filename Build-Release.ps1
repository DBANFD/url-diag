param()
$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    cargo fmt --all --check
    if ($LASTEXITCODE) { throw 'Formatting failed' }
    cargo clippy --locked --all-targets -- -D warnings
    if ($LASTEXITCODE) { throw 'Clippy failed' }
    cargo test --locked
    if ($LASTEXITCODE) { throw 'Tests failed' }
    cargo build --release --locked
    if ($LASTEXITCODE) { throw 'Build failed' }
    Get-FileHash target/release/url-diag.exe -Algorithm SHA256
} finally {
    Pop-Location
}
