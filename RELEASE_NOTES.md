# URL Diag v0.2.0

Independent terminal dashboard and CLI for non-Microsoft service URL connectivity.

## New in 0.2.0

- Test through an HTTP CONNECT proxy: `--proxy env`, `--proxy system` (Windows WinHTTP) or `--proxy http://host:port`, including `ui --proxy ...` for the dashboard. Direct stays the default.
- Test a documented path with `--path` and `--method get`; 3xx responses show where they redirect (query strings removed, not followed).
- Self-contained HTML reports with `--html`.
- PAC/WPAD and authenticated proxies are not supported. Proxied hosts are tested by name, so per-IP results apply only to direct routes.

## Included since 0.1.0

- 18 service groups, including 67 URL feeds across eight groups and explicit IP-only coverage notes for ten groups.
- Custom tenant hostname input, DNS/TCP/verified TLS/HTTPS modes, repeated-test presets, colored outcomes and per-IP evidence.
- JSON/CSV exports and flushed cancellation journals. Direct connections by default; HTTP error responses do not automatically fail transport.

Windows x64 ZIP, Linux x64 (glibc 2.35+) tar.gz, macOS Intel and Apple Silicon tar.gz are supported by release packaging. Extract and run `url-diag.exe` or `./url-diag`; Rust is not required to run the binary. macOS builds use macOS 15; older versions are not qualified. No Windows ARM or Linux ARM native builds are provided.

Builds are unsigned and not Apple-notarized. Verify SHA256SUMS.txt; hashes detect mismatches but do not establish publisher authenticity. Source builds are available. No vendor packages or diagnostic evidence are included. Native CI and executable smoke checks do not prove connectivity in your environment.
