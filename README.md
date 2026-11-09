# URL Diag

A terminal dashboard and CLI for troubleshooting connectivity to non-Microsoft cloud service groups. Built in Rust, with the familiar cyan menus, per-IP results and latency display from [Defender Diag](https://github.com/DBANFD/defender-diag).

Source version **0.2.0**. MIT licensed. No vendor tools, credentials or diagnostic evidence are bundled.

## Run

Build with Rust stable: `cargo build --release --locked`. Run `target/release/url-diag.exe` on Windows or `./target/release/url-diag` on Linux/macOS. Rust is only needed to build; the resulting executable runs without a Rust installation. Native OS trust certificates are required. Linux binaries depend on their build platform's libc.

Without arguments the app opens its dashboard:

1. Choose a service group, browse all URL feeds, or enter a custom service/tenant hostname.
2. Review the feed description and concrete host list. Space selects; **A** selects all/none; **X** shows excluded patterns.
3. Press Enter to configure mode, repetitions, delay, timeout, port and concurrency. Presets: **1** Quick, **2** TLS soak, **3** Extended, **4** Overnight.
4. Select **START**. The header shows green **PASS**, red **FAIL** or yellow **INCOMPLETE**. These are selected-stage, per-address results, not application-health verdicts.
5. Use arrows to inspect results, **D** for certificate/error details and **S** to export JSON/CSV. **Esc** cancels a running test. Completed attempts remain in the local JSONL journal.

```text
url-diag groups
url-diag feeds --filter zoom
url-diag test zoom.us --mode https --count 3
url-diag test tenant.sentinelone.net --preset tls-soak --journal attempts.jsonl
url-diag test service.example --resolve-ip 192.0.2.10 --port 443
url-diag test service.example --https --method get --path /api/health --html report.html
url-diag test zoom.us --https --proxy system
url-diag ui --proxy http://proxy.example:8080
url-diag edl --feed https://saasedl.paloaltonetworks.com/feeds/androidenterprise/all/url --mode https --output results.json --csv attempts.csv
url-diag profile custom --config examples/custom.json --mode tls
```

Replace illustrative tenant/service hostnames and reserved IP addresses with your documented targets. SentinelOne is supported through custom tenant hostnames; this source has no SentinelOne feed group. No cloud login is required.

## Service coverage

The reviewed [EDL Hosting Service inventory](https://docs.paloaltonetworks.com/resources/edl-hosting-service), retrieved 2026-11-05, supplies **67 URL feeds across eight groups**: Android Enterprise, Broadcom, Palo Alto Networks services, Samsung Knox, Salesforce, Cisco Webex, Zoom and Zscaler.

Ten further groups are visible with **IP-only coverage**: Akamai, Amazon Web Services, Atlassian Cloud, Datadog, Fastly, Google Cloud, Google Workspace, HashiCorp, Okta and Oracle Cloud. Enter a documented hostname to test them. The tool does not expand, scan or pretend to TLS-test CIDR ranges.

Microsoft 365, Azure, Defender, Intune and Microsoft-owned GitHub feeds are excluded. The feed host and the described service are different things. Dependencies listed by an included service are retained regardless of domain ownership; membership does not establish publisher ownership. Custom hostnames are operator-supplied and syntax-validated, not classified by corporate ownership. There are no Microsoft presets or Analyzer integrations here.

See [SOURCES.md](SOURCES.md) for the explicit group classification and update process. “All” means within the selected feed scope, not every product, region or tenant. Wildcards are never changed into parent domains. HTTP-only URLs, paths, IP ranges and malformed entries are reported as excluded.

## What results mean

- DNS uses the OS resolver and records all returned addresses and lookup duration. Each resolved IP is tested independently with the original hostname and SNI.
- TCP and verified TLS have separate deadlines and failure codes. Native trust roots are loaded into rustls; certificate checks are never disabled. Trusted handshakes expose TLS version, cipher, subject, issuer and expiry.
- HTTPS sends **HEAD /** using HTTP/1.1 by default. Use `--path` and `--method get` to test a documented path; the path must be ASCII without spaces or a fragment. A 3xx response records its Location (query and fragment removed) without following it. Any valid HTTP response completes transport, including 403, 404 and 5xx. Non-2xx responses need application-level interpretation; the tool has no provider-specific “expected error” exemptions.
- PASS means all observed attempts completed the selected stages in a finished run. FAIL means at least one address attempt failed; another address may still work. INCOMPLETE means cancellation, execution failure or missing final evidence. Failed alternate IPs remain visible.
- Summaries include success percentage, min/max/average and nearest-rank p95 for successful attempts. Host summaries are weighted by individual addresses/attempts, not a single service-health score. Connection total latency excludes DNS; DNS-only totals are lookup latency.

CLI exit codes: **0** all attempts succeeded, **1** any failed attempt or cancellation, **2** configuration/report error. Closing the dashboard normally returns 0; consult its result/report for diagnostic outcomes.

## Evidence and privacy

Dashboard runs create local `results/attempts-*.jsonl` journals. CLI journaling requires `--journal`. Final JSON/CSV exports are explicit, create-new and never overwrite prior evidence. Missing journal `end` means incomplete. No uploads are performed.

Reports can contain internal hostnames, IPs and certificate metadata. Keep them private and review before sharing; no anonymity guarantee is made. Only proxy environment variable names are exported, never proxy values or credentials. Feed entries containing credentials, query strings or control codes are redacted. See [REPORT_SCHEMA.md](REPORT_SCHEMA.md).

## Limits

Connections are direct unless `--proxy` is set: `env` (HTTPS_PROXY or ALL_PROXY with NO_PROXY), `system` (Windows WinHTTP and its bypass list) or `http://host:port`. Proxied hosts are reached by name through HTTP CONNECT, so per-IP results apply only to direct routes. PAC/WPAD, authenticated proxies and credentials in proxy URLs are not supported; a 407 reply is reported as PROXY_AUTH_REQUIRED. Results need not match an application's route, identity or certificate pinning.

No DNS server override or CNAME chain display, redirect following, GET fallback, request bodies, HTTP/2/3, invalid-certificate inspection, revocation fetching, packet capture or application authentication. OS resolver caching affects repeated tests. Some URL feeds contain only excluded patterns and cannot run until you supply real tenant/service hostnames. A maximum of 256 concrete feed targets, 1,000 rounds and 64 concurrent probes is enforced; broad feeds over the limit require a narrower category. No scheduled background tests.

## Development

```text
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --release --locked
```

Offline tests use synthetic data and loopback services; live network checks are separate and optional. GitHub CI runs on Windows, Linux and macOS. See [TESTING.md](TESTING.md), [CHANGELOG.md](CHANGELOG.md) and [NOTICE.md](NOTICE.md).
