# Changelog

## 0.2.0 - 2026-11-09

- Optional HTTP CONNECT proxy routing for tests, feeds, profiles and the dashboard: `--proxy env` (HTTPS_PROXY/ALL_PROXY with NO_PROXY), `--proxy system` (Windows WinHTTP with its bypass list) or `--proxy http://host:port`. Direct remains the default.
- Named proxy failures with guidance, including PROXY_AUTH_REQUIRED (407) and PROXY_CONNECT_REJECTED. Credentials are never accepted or exported.
- `--path` and `--method get` test a documented HTTPS path. 3xx responses record a sanitized redirect location without following it.
- Self-contained HTML reports with `--html`; the dashboard saves HTML next to JSON and CSV.

## 0.1.0 - 2026-11-05

- Initial independent URL Diag repository, based on selected MIT-licensed Defender Diag components.
- Non-Microsoft service browser: 18 groups, 67 URL feeds, explicit IP-only coverage notes and custom tenant hostname entry.
- Direct DNS/TCP/verified TLS/HTTPS testing, repeated presets, bounded concurrency and per-IP results.
- Colored PASS/FAIL/INCOMPLETE header, latency display, detailed errors, certificate evidence, cancellation and create-new JSON/CSV/JSONL reporting.
- Explicit feed allowlist and source classification, synthetic/loopback tests and cross-platform CI.
