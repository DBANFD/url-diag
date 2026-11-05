use anyhow::Result;
use serde::Serialize;
use std::{collections::BTreeMap, net::IpAddr, path::Path};

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

#[derive(Debug, Clone, Serialize)]
pub struct Failure {
    pub code: String,
    pub message: String,
}
impl Failure {
    pub fn new(code: &str, message: impl ToString) -> Self {
        Self {
            code: code.into(),
            message: message.to_string(),
        }
    }
}
#[derive(Debug, Clone, Serialize)]
pub struct DnsResult {
    pub hostname: String,
    pub iteration: u16,
    pub timestamp: String,
    pub source: String,
    pub duration_ms: f64,
    pub addresses: Vec<IpAddr>,
    pub error: Option<Failure>,
}
#[derive(Debug, Clone, Serialize)]
pub struct Certificate {
    pub subject: String,
    pub issuer: String,
    pub expires: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct Attempt {
    pub http_method: Option<String>,
    pub http_path: Option<String>,
    pub assessment: String,
    pub diagnostic_note: String,
    pub hostname: String,
    pub ip: Option<IpAddr>,
    pub port: u16,
    pub iteration: u16,
    pub timestamp: String,
    pub route: String,
    pub tcp_ms: Option<f64>,
    pub tls_ms: Option<f64>,
    pub http_ms: Option<f64>,
    pub total_ms: f64,
    pub tls_version: Option<String>,
    pub cipher: Option<String>,
    pub certificates: Vec<Certificate>,
    pub http_status: Option<u16>,
    pub success: bool,
    pub error: Option<Failure>,
}
impl Attempt {
    pub fn new(host: String, ip: Option<IpAddr>, port: u16, iteration: u16) -> Self {
        Self {
            http_method: None,
            http_path: None,
            assessment: "not_assessed".into(),
            diagnostic_note: String::new(),
            hostname: host,
            ip,
            port,
            iteration,
            timestamp: chrono::Utc::now().to_rfc3339(),
            route: "direct".into(),
            tcp_ms: None,
            tls_ms: None,
            http_ms: None,
            total_ms: 0.,
            tls_version: None,
            cipher: None,
            certificates: Vec::new(),
            http_status: None,
            success: false,
            error: None,
        }
    }
}
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
        "url-diag {} | {} | DIRECT | {}",
        r.tool_version, r.platform, r.mode
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
