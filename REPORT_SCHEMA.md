# URL Diag report schema v2

Reuses the MIT-licensed Defender Diag connectivity structure; URL Diag versions are independent.

UTF-8 JSON, schema_version = 2. Additive fields may appear; consumers should ignore unknown fields.

| Field | Type / meaning |
|---|---|
| tool_version | string, Cargo package version |
| started_at, completed_at | UTC RFC3339 timestamps |
| platform | OS identifier |
| mode | dns, dns_tcp, dns_tcp_tls or dns_tcp_tls_https |
| warnings | array of diagnostic limitations/trust-loading notes |
| proxy | environment_variables_present (names only), note |
| dns | array of DNS observations |
| attempts | array of individual connection attempts or hostname-only DNS failures |
| summaries | map keyed by host:hostname or ip:hostname/address |

DNS observation: hostname, iteration (1-based), timestamp (UTC), source (operating system or override (DNS skipped)), duration_ms (number), addresses (unique IP strings), error (null or failure).

Attempt: hostname, ip (string or null on DNS failure / DNS-only probes), port, iteration, timestamp (UTC start), route (always direct), tcp_ms/tls_ms/http_ms (number or null if not attempted), total_ms (number), tls_version/cipher (string or null), certificates (array), http_status (integer or null), success (boolean), error (null or failure).

Certificate: subject, issuer, expires (strings parsed from X.509). Only available after trusted handshake. No assertion of root presence or revocation status.

Failure: code (stable string), message (diagnostic detail; not stable for parsing). Codes: DNS_TIMEOUT, DNS_LOOKUP_FAILED, DNS_NO_ADDRESSES, TCP_TIMEOUT, TCP_REFUSED, TCP_UNREACHABLE, TCP_PERMISSION_DENIED, TCP_RESET, TCP_OTHER, TLS_INVALID_NAME, TLS_TIMEOUT, TLS_CERTIFICATE_INVALID, TLS_HANDSHAKE_FAILED, HTTP_IO, HTTP_TIMEOUT, HTTP_HEADERS_TOO_LARGE, HTTP_INVALID_RESPONSE. Configuration/report setup failures are emitted to stderr as CONFIG_OR_REPORT_ERROR, outside the report.

Summary: attempts and successes (integers), success_percent (number 0..100), min_ms/max_ms/average_ms/p95_ms (number or null), failures (map of code to count). Latencies include successful connection attempts only; see README for DNS and hostname weighting.

CSV: timestamp,hostname,ip,port,iteration,route,tcp_ms,tls_ms,http_ms,total_ms,http_status,success,error_code,http_method,http_path,assessment. Empty fields represent null. All attempts are exported; detailed certificates, errors, DNS observations and summaries are JSON-only. The first 13 CSV columns retain their previous order; schema 2 appends method, path and assessment.

Optional source_feed: url, retrieved_at (UTC RFC3339), sha256 (UTF-8 feed bytes), catalog_source, targets (eligible concrete hosts), and skipped (entry/reason pairs). It is absent for non-feed runs. Imported inventory may include hosts the user deselected; attempts record what was actually tested. User-added concrete hosts can also appear in attempts. Excluded entries never enter success denominators. Credential/query-bearing or control-character entries are redacted.

DNS-only mode emits one hostname-level row per lookup. Its total_ms is DNS elapsed time; tcp_ms/tls_ms/http_ms are null. Other modes retain per-IP rows and connection-stage timing semantics. Interactive mode exit 0 means the user closed the UI normally; use reports to assess diagnostic outcomes. Scripted commands retain exit 0/1/2 semantics.

Schema 2 includes http_method and http_path (null until an HTTP request is attempted), assessment, and diagnostic_note to JSON attempts. CSV appends http_method,http_path,assessment. success remains the raw selected-stage result; assessments never modify it. Assessment values: not_assessed (manually constructed row), stage_succeeded, response_received, review_http, transport_failure. All 5xx statuses require review; TLS errors always remain failures. Raw HTTP status and failure code are preserved.

## Incremental journal schema 1
Optional CLI --journal / automatic UI results/attempts-*.jsonl writes one envelope per line: journal_schema=1, kind=start|dns|attempt|end, data=object. Start includes timestamp, tool version, hosts, effective mode/count/interval/stage timeout/concurrency. DNS and attempt payloads use the existing types above. End records completion time and attempt count. Missing end is an incomplete run; ignore an incomplete trailing line after a crash. No final success percentage is inferred from an unfinished journal. Files use create-new and flush every record.
