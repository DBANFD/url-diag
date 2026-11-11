use anyhow::Result;
use serde::Serialize;
use std::{collections::BTreeMap, path::Path};

/// One flushed JSON object per line. Missing end record means incomplete run.
pub struct Journal(std::fs::File);
impl Journal {
    pub fn create(path: &Path) -> Result<Self> {
        Ok(Self(
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)?,
        ))
    }
    pub fn write(&mut self, kind: &str, data: impl Serialize) -> Result<()> {
        use std::io::Write;
        serde_json::to_writer(
            &mut self.0,
            &serde_json::json!({"journal_schema":1,"kind":kind,"data":data}),
        )?;
        self.0.write_all(b"\n")?;
        self.0.flush()?;
        Ok(())
    }
}

pub use diag_core::types::{Attempt, Certificate, DnsResult, Failure};
#[derive(Serialize)]
pub struct Report {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_feed: Option<crate::edl::FeedSnapshot>,
    pub schema_version: u32,
    pub tool_version: String,
    pub started_at: String,
    pub completed_at: String,
    pub platform: String,
    pub mode: String,
    pub warnings: Vec<String>,
    pub proxy: crate::proxy::ProxyInfo,
    pub dns: Vec<DnsResult>,
    pub attempts: Vec<Attempt>,
    pub summaries: BTreeMap<String, crate::statistics::Summary>,
}
pub fn export(report: &Report, json: Option<&Path>, csv: Option<&Path>) -> Result<()> {
    // CreateNew preserves previous evidence. On an I/O failure a partial file may remain.
    if let Some(path) = json {
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        serde_json::to_writer_pretty(f, report)?;
    }
    if let Some(path) = csv {
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        let mut w = csv::Writer::from_writer(f);
        w.write_record([
            "timestamp",
            "hostname",
            "ip",
            "port",
            "iteration",
            "route",
            "tcp_ms",
            "tls_ms",
            "http_ms",
            "total_ms",
            "http_status",
            "success",
            "error_code",
            "http_method",
            "http_path",
            "assessment",
            "proxy_connect_ms",
            "redirect_location",
        ])?;
        for a in &report.attempts {
            let val = |x: Option<f64>| x.map(|v| v.to_string()).unwrap_or_default();
            w.write_record([
                a.timestamp.clone(),
                a.hostname.clone(),
                a.ip.map(|v| v.to_string()).unwrap_or_default(),
                a.port.to_string(),
                a.iteration.to_string(),
                a.route.clone(),
                val(a.tcp_ms),
                val(a.tls_ms),
                val(a.http_ms),
                a.total_ms.to_string(),
                a.http_status.map(|v| v.to_string()).unwrap_or_default(),
                a.success.to_string(),
                a.error.as_ref().map(|e| e.code.clone()).unwrap_or_default(),
                a.http_method.clone().unwrap_or_default(),
                a.http_path.clone().unwrap_or_default(),
                a.assessment.clone(),
                val(a.proxy_connect_ms),
                a.redirect_location.clone().unwrap_or_default(),
            ])?;
        }
        w.flush()?;
    }
    Ok(())
}
pub fn console(r: &Report) {
    println!(
        "Proxy environment variables present: {:?}",
        r.proxy.environment_variables_present
    );
    println!("{}", r.proxy.note);
    println!(
        "url-diag {} | {} | {} | {}",
        r.tool_version,
        r.platform,
        r.proxy
            .proxy
            .as_deref()
            .map_or("DIRECT".to_string(), |p| format!("PROXY {p}")),
        r.mode
    );
    for w in &r.warnings {
        println!("NOTE: {w}");
    }
    for d in &r.dns {
        println!(
            "DNS {} round {} {:.1} ms {:?} {}",
            d.hostname,
            d.iteration,
            d.duration_ms,
            d.addresses,
            d.error.as_ref().map(|e| e.code.as_str()).unwrap_or("OK")
        );
    }
    for a in &r.attempts {
        let alternative = crate::endpoints::alternate_address_note(a, &r.attempts);
        if !alternative.is_empty() {
            println!("  ADDRESS NOTE: {alternative}");
        }
        println!(
            "  {}: {} | request {:?} {:?}",
            a.assessment, a.diagnostic_note, a.http_method, a.http_path
        );
        println!(
            "{} {} {:?}:{} round {} TCP={:?} TLS={:?} HTTP={:?} {}",
            a.timestamp,
            a.hostname,
            a.ip,
            a.port,
            a.iteration,
            a.tcp_ms,
            a.tls_ms,
            a.http_status,
            a.error
                .as_ref()
                .map(|e| format!("{}: {}", e.code, e.message))
                .unwrap_or_else(|| "OK".into())
        );
        if let Some(v) = &a.tls_version {
            println!("  {v} {:?}; validated certificate chain:", a.cipher);
        }
        for c in &a.certificates {
            println!(
                "  subject={} issuer={} expires={}",
                c.subject, c.issuer, c.expires
            );
        }
    }
    for (key, s) in &r.summaries {
        println!(
            "{key}: {}/{} ({:.1}%) total successful latency ms min={:?} max={:?} avg={:?} p95={:?}; failures={:?}",
            s.successes,
            s.attempts,
            s.success_percent,
            s.min_ms,
            s.max_ms,
            s.average_ms,
            s.p95_ms,
            s.failures
        );
    }
}

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c if c.is_control() && c != '\n' => out.push(' '),
            c => out.push(c),
        }
    }
    out
}
fn ms(v: Option<f64>) -> String {
    v.map(|x| format!("{x:.1}")).unwrap_or_else(|| "-".into())
}
/// Overall label for a finished report: PASS only when every attempt succeeded.
pub fn outcome(r: &Report) -> &'static str {
    if r.completed_at.is_empty() || r.attempts.is_empty() {
        "INCOMPLETE"
    } else if r.attempts.iter().all(|a| a.success) {
        "PASS"
    } else {
        "FAIL"
    }
}
/// Self-contained HTML report: no scripts, no external resources, all values escaped.
pub fn render_html(r: &Report) -> String {
    let outcome = outcome(r);
    let colour = match outcome {
        "PASS" => "#1f8a4c",
        "FAIL" => "#c0392b",
        _ => "#b7950b",
    };
    let route = r.proxy.proxy.as_deref().map_or("DIRECT".to_string(), |p| {
        format!("PROXY {p} ({})", r.proxy.source)
    });
    let mut h = String::new();
    h.push_str("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
    h.push_str("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">");
    h.push_str(&format!(
        "<title>{} report</title>",
        esc(env!("CARGO_PKG_NAME"))
    ));
    h.push_str("<style>body{font:14px system-ui,sans-serif;max-width:1200px;margin:32px auto;padding:0 16px;color:#1d2330}h1{margin-bottom:4px}h2{margin-top:32px}table{border-collapse:collapse;width:100%;font-size:12px}th,td{border-bottom:1px solid #d8dce6;padding:6px 8px;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#f2f4f8}.badge{display:inline-block;color:#fff;font-weight:700;padding:4px 12px;border-radius:4px}.ok{color:#1f8a4c}.bad{color:#c0392b}.note{background:#f6f7fa;padding:12px;border-radius:6px}@media print{h2{break-after:avoid}}</style>");
    h.push_str(&format!(
        "<h1>{} {}</h1>",
        esc(env!("CARGO_PKG_NAME")),
        esc(&r.tool_version)
    ));
    h.push_str(&format!(
        "<p><span class=\"badge\" style=\"background:{colour}\">{outcome}</span> {} | {} | {} | {} attempts</p>",
        esc(&r.platform),
        esc(&route),
        esc(&r.mode),
        r.attempts.len()
    ));
    h.push_str(&format!(
        "<p>Started {} | Completed {}</p>",
        esc(&r.started_at),
        esc(if r.completed_at.is_empty() {
            "(not completed)"
        } else {
            &r.completed_at
        })
    ));
    h.push_str("<p class=\"note\">PASS means every observed attempt completed the selected stages. It is not proof of service or application health. FAIL means at least one address or round failed; another address may still work.</p>");
    h.push_str(&format!("<p class=\"note\">{}</p>", esc(&r.proxy.note)));
    h.push_str("<h2>Summary by host</h2><table><tr><th>Host / key</th><th>Success</th><th>Min ms</th><th>Avg ms</th><th>p95 ms</th><th>Max ms</th><th>Failures</th></tr>");
    for (key, s) in &r.summaries {
        let failures = s
            .failures
            .iter()
            .map(|(k, v)| format!("{k}: {v}"))
            .collect::<Vec<_>>()
            .join(", ");
        h.push_str(&format!(
            "<tr><td>{}</td><td class=\"{}\">{}/{} ({:.1}%)</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            esc(key),
            if s.successes == s.attempts { "ok" } else { "bad" },
            s.successes,
            s.attempts,
            s.success_percent,
            ms(s.min_ms),
            ms(s.average_ms),
            ms(s.p95_ms),
            ms(s.max_ms),
            esc(&failures)
        ));
    }
    h.push_str("</table><h2>Attempts</h2><table><tr><th>Time</th><th>Host</th><th>Address</th><th>Round</th><th>Route</th><th>TCP</th><th>CONNECT</th><th>TLS</th><th>HTTP</th><th>Status</th><th>Result</th><th>Detail</th></tr>");
    for a in &r.attempts {
        let detail = a.error.as_ref().map_or_else(
            || match &a.redirect_location {
                Some(l) => format!(
                    "{} {} redirects to {l} (not followed)",
                    a.http_method.as_deref().unwrap_or(""),
                    a.http_path.as_deref().unwrap_or("")
                ),
                None => a.tls_version.clone().unwrap_or_default(),
            },
            |e| format!("{}: {}", e.code, e.message),
        );
        h.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td class=\"{}\">{}</td><td>{}</td></tr>",
            esc(&a.timestamp),
            esc(&a.hostname),
            esc(&a.ip.map(|i| i.to_string()).unwrap_or_else(|| "-".into())),
            a.iteration,
            esc(&a.route),
            ms(a.tcp_ms),
            ms(a.proxy_connect_ms),
            ms(a.tls_ms),
            ms(a.http_ms),
            a.http_status.map(|s| s.to_string()).unwrap_or_else(|| "-".into()),
            if a.success { "ok" } else { "bad" },
            if a.success { "OK" } else { "FAILED" },
            esc(&detail)
        ));
    }
    h.push_str("</table><h2>DNS</h2><table><tr><th>Host</th><th>Round</th><th>ms</th><th>Addresses</th><th>Error</th></tr>");
    for d in &r.dns {
        let addrs = d
            .addresses
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        h.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{:.1}</td><td>{}</td><td>{}</td></tr>",
            esc(&d.hostname),
            d.iteration,
            d.duration_ms,
            esc(&addrs),
            esc(&d
                .error
                .as_ref()
                .map(|e| format!("{}: {}", e.code, e.message))
                .unwrap_or_default())
        ));
    }
    h.push_str("</table><h2>Notes</h2><ul>");
    for w in &r.warnings {
        h.push_str(&format!("<li>{}</li>", esc(w)));
    }
    h.push_str("</ul><p>Reports can contain internal hostnames, IP addresses and certificate details. Review before sharing.</p></html>\n");
    h
}
pub fn export_html(report: &Report, path: &Path) -> Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    f.write_all(render_html(report).as_bytes())?;
    Ok(())
}
