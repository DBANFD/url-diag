# Changelog

## 0.3.0 - 2026-11-11

- Basic proxy authentication. Credentials come from `DIAG_PROXY_USER` and `DIAG_PROXY_PASSWORD`, or from the userinfo part of HTTPS_PROXY/ALL_PROXY with `--proxy env`. They are still refused on the command line and never exported. New failure code PROXY_AUTH_FAILED; 407 messages list the schemes the proxy offered. Reports add `proxy.authentication` ("none" or "basic").
- HTTPS probes no longer send the default port in the Host header (`Host: example.com` instead of `Host: example.com:443`), matching what browsers and agents send. Non-default ports are still included.
- Response headers are read in chunks instead of one byte at a time.
- DNS, TCP, TLS, HTTP, proxy and statistics code moved to the shared [diag-core](https://github.com/DBANFD/diag-core) crate, pinned by commit. The dashboard source is split into state, input and render modules.
- Release builds use LTO and are stripped. The toolchain is pinned in `rust-toolchain.toml` and the minimum supported Rust version (1.88) is declared.
- CI: actions pinned by commit, Dependabot for cargo and actions, a `cargo audit` job, build provenance attestation on release archives, and two new release targets (Windows ARM64, static musl Linux) that cannot block a release while they are new.

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
