# URL Diag v0.1.0

Independent terminal dashboard and CLI for non-Microsoft service URL connectivity.

- 18 service groups, including 67 URL feeds across eight groups and explicit IP-only coverage notes for ten groups.
- Custom tenant hostname input, DNS/TCP/verified TLS/HTTPS modes, repeated-test presets, colored outcomes and per-IP evidence.
- JSON/CSV exports and flushed cancellation journals. Direct connections only; HTTP error responses do not automatically fail transport.

Windows x64 ZIP, Linux x64 (glibc 2.35+) tar.gz, macOS Intel and Apple Silicon tar.gz are supported by release packaging. Extract and run `url-diag.exe` or `./url-diag`; Rust is not required to run the binary. macOS builds use macOS 15; older versions are not qualified. No Windows ARM or Linux ARM native builds are provided.

Builds are unsigned and not Apple-notarized. Verify SHA256SUMS.txt; hashes detect mismatches but do not establish publisher authenticity. Source builds are available. No vendor packages or diagnostic evidence are included. Native CI and executable smoke checks do not prove connectivity in your environment.
