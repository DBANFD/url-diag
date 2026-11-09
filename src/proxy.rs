//! Explicit HTTP CONNECT proxy routing. Direct remains the default.
//!
//! Supported sources: a literal `http://host:port` URL, the HTTPS_PROXY/ALL_PROXY
//! environment variables (with NO_PROXY), or the Windows WinHTTP configuration
//! (`netsh winhttp show proxy`). PAC/WPAD scripts and authenticated proxies are not
//! supported; a 407 response is reported as PROXY_AUTH_REQUIRED.
use crate::reporting::Failure;
use serde::Serialize;
use std::{fmt, str::FromStr, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum ProxyChoice {
    #[default]
    Direct,
    Env,
    System,
    Url(Endpoint),
}
impl FromStr for ProxyChoice {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "direct" | "none" => Ok(Self::Direct),
            "env" => Ok(Self::Env),
            "system" | "winhttp" => Ok(Self::System),
            _ => Endpoint::parse(s).map(Self::Url),
        }
    }
}
impl fmt::Display for ProxyChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct => write!(f, "direct"),
            Self::Env => write!(f, "env"),
            Self::System => write!(f, "system"),
            Self::Url(e) => write!(f, "{e}"),
        }
    }
}
pub fn parse_choice(s: &str) -> Result<ProxyChoice, String> {
    s.parse()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}
impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "http://[{}]:{}", self.host, self.port)
        } else {
            write!(f, "http://{}:{}", self.host, self.port)
        }
    }
}
impl Endpoint {
    /// Accepts `http://host:port`, `host:port` or `[v6]:port`. Credentials, paths,
    /// queries and HTTPS-to-proxy are rejected so nothing secret reaches reports.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let s = raw.trim();
        let rest = match s.split_once("://") {
            Some((scheme, rest)) if scheme.eq_ignore_ascii_case("http") => rest,
            Some((scheme, _)) => {
                return Err(format!(
                    "unsupported proxy scheme '{scheme}': only http:// CONNECT proxies are supported"
                ));
            }
            None => s,
        };
        let rest = rest.strip_suffix('/').unwrap_or(rest);
        if rest.contains('@') {
            return Err("proxy credentials are not supported; remove user:password@".into());
        }
        if rest.contains(['/', '?', '#']) || rest.chars().any(|c| c.is_control() || c == ' ') {
            return Err("proxy must be host:port without a path".into());
        }
        let (host, port) = if let Some(v6) = rest.strip_prefix('[') {
            let (host, port) = v6.split_once("]:").ok_or("expected [ipv6]:port")?;
            (host.to_string(), port)
        } else {
            let (host, port) = rest
                .rsplit_once(':')
                .ok_or("proxy needs an explicit port, e.g. http://proxy.example:8080")?;
            (host.to_string(), port)
        };
        let port: u16 = port.parse().map_err(|_| "invalid proxy port".to_string())?;
        if host.is_empty() || port == 0 {
            return Err("proxy host and port are required".into());
        }
        Ok(Self {
            host: host.to_ascii_lowercase(),
            port,
        })
    }
}

/// Resolved routing for one run: which proxy (if any) applies, plus bypass rules.
#[derive(Clone, Debug, Default)]
pub struct Plan {
    pub source: String,
    pub endpoint: Option<Endpoint>,
    pub bypass: Vec<String>,
    pub bypass_local: bool,
}
impl Plan {
    pub fn route(&self, host: &str) -> Option<&Endpoint> {
        let endpoint = self.endpoint.as_ref()?;
        let host = host.to_ascii_lowercase();
        if self.bypass_local && !host.contains('.') {
            return None;
        }
        let bypassed = self.bypass.iter().any(|rule| {
            let rule = rule.trim().trim_start_matches("*.").trim_start_matches('.');
            rule == "*"
                || (!rule.is_empty() && (host == rule || host.ends_with(&format!(".{rule}"))))
        });
        (!bypassed).then_some(endpoint)
    }
}

pub fn plan(choice: &ProxyChoice) -> Result<Plan, String> {
    match choice {
        ProxyChoice::Direct => Ok(Plan {
            source: "direct".into(),
            ..Default::default()
        }),
        ProxyChoice::Url(e) => Ok(Plan {
            source: "explicit".into(),
            endpoint: Some(e.clone()),
            ..Default::default()
        }),
        ProxyChoice::Env => {
            let get = |names: &[&str]| {
                names
                    .iter()
                    .find_map(|n| std::env::var(n).ok().filter(|v| !v.trim().is_empty()))
            };
            let endpoint = get(&["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"])
                .map(|v| Endpoint::parse(&v).map_err(|e| format!("HTTPS_PROXY/ALL_PROXY: {e}")))
                .transpose()?;
            let bypass = get(&["NO_PROXY", "no_proxy"])
                .map(|v| {
                    v.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default();
            Ok(Plan {
                source: "environment".into(),
                endpoint,
                bypass,
                bypass_local: false,
            })
        }
        ProxyChoice::System => system(),
    }
}

#[cfg(windows)]
fn system() -> Result<Plan, String> {
    let out = std::process::Command::new("netsh")
        .args(["winhttp", "show", "proxy"])
        .output()
        .map_err(|e| format!("could not read WinHTTP proxy: {e}"))?;
    Ok(parse_winhttp(&String::from_utf8_lossy(&out.stdout)))
}
#[cfg(not(windows))]
fn system() -> Result<Plan, String> {
    Err("--proxy system reads Windows WinHTTP settings; use --proxy env or an explicit http://host:port on this platform".into())
}

/// Parses `netsh winhttp show proxy` output. Per-scheme lists use the https= entry.
pub fn parse_winhttp(text: &str) -> Plan {
    let mut plan = Plan {
        source: "winhttp".into(),
        ..Default::default()
    };
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        if key.starts_with("proxy server") {
            let pick = value
                .split(';')
                .map(str::trim)
                .find(|v| v.to_ascii_lowercase().starts_with("https="))
                .or_else(|| value.split(';').map(str::trim).find(|v| !v.contains('=')))
                .map(|v| v.split_once('=').map_or(v, |(_, x)| x));
            plan.endpoint = pick.and_then(|v| Endpoint::parse(v).ok());
        } else if key.starts_with("bypass list") {
            for item in value
                .split(';')
                .map(str::trim)
                .filter(|s| !s.is_empty() && *s != "(none)")
            {
                if item.eq_ignore_ascii_case("<local>") {
                    plan.bypass_local = true;
                } else {
                    plan.bypass.push(item.to_string());
                }
            }
        }
    }
    plan
}

#[derive(Serialize)]
pub struct ProxyInfo {
    pub environment_variables_present: Vec<String>,
    /// direct, explicit, environment or winhttp.
    pub source: String,
    /// host:port only; credentials are never accepted or exported.
    pub proxy: Option<String>,
    pub bypass_rules: usize,
    pub note: String,
}
pub fn detect() -> ProxyInfo {
    describe(&Plan {
        source: "direct".into(),
        ..Default::default()
    })
}
pub fn describe(plan: &Plan) -> ProxyInfo {
    // Intentionally export variable names only, never values or NO_PROXY contents.
    let names = [
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "https_proxy",
        "http_proxy",
        "all_proxy",
        "no_proxy",
    ];
    let note = match &plan.endpoint {
        None => "All probes are DIRECT. This is not necessarily the tested application's effective proxy configuration. Use --proxy env, --proxy system (WinHTTP) or --proxy http://host:port to test through a proxy.".into(),
        Some(e) => format!("Probes use HTTP CONNECT through {e} ({}) unless a bypass rule matches. The proxy resolves target names, so per-IP results are not available for proxied hosts. PAC/WPAD and proxy authentication are not supported.", plan.source),
    };
    ProxyInfo {
        environment_variables_present: names
            .iter()
            .filter(|n| std::env::var_os(n).is_some())
            .map(|n| n.to_string())
            .collect(),
        source: plan.source.clone(),
        proxy: plan.endpoint.as_ref().map(|e| e.to_string()),
        bypass_rules: plan.bypass.len() + usize::from(plan.bypass_local),
        note,
    }
}

/// Connect to the proxy and open a CONNECT tunnel. Returns the tunnel and the
/// time spent on the proxy TCP connect and the CONNECT exchange.
pub async fn tunnel(
    proxy: &Endpoint,
    host: &str,
    port: u16,
    limit: Duration,
) -> Result<(tokio::net::TcpStream, f64, f64), Failure> {
    let start = std::time::Instant::now();
    let connect = tokio::net::TcpStream::connect((proxy.host.as_str(), proxy.port));
    let mut stream = match tokio::time::timeout(limit, connect).await {
        Err(_) => {
            return Err(Failure::new(
                "PROXY_TCP_TIMEOUT",
                format!("connect to proxy {proxy} exceeded deadline"),
            ));
        }
        Ok(Err(e)) => {
            return Err(Failure::new(
                &format!("PROXY_{}", crate::tcp::classify(&e)),
                format!("proxy {proxy}: {e}"),
            ));
        }
        Ok(Ok(s)) => s,
    };
    let tcp_ms = start.elapsed().as_secs_f64() * 1000.;
    let start = std::time::Instant::now();
    let exchange = async {
        let request = format!(
            "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: {}/{}\r\nProxy-Connection: keep-alive\r\n\r\n",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        );
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| Failure::new("PROXY_IO", e))?;
        // Read byte by byte so no tunnel bytes are consumed past the header block.
        let mut buf = Vec::new();
        loop {
            let b = stream
                .read_u8()
                .await
                .map_err(|e| Failure::new("PROXY_IO", e))?;
            buf.push(b);
            if buf.ends_with(b"\r\n\r\n") {
                break;
            }
            if buf.len() >= 16384 {
                return Err(Failure::new(
                    "PROXY_INVALID_RESPONSE",
                    "CONNECT response headers exceed 16 KiB",
                ));
            }
        }
        let status = crate::http::parse_status(&buf)
            .map_err(|f| Failure::new("PROXY_INVALID_RESPONSE", f.message))?;
        match status {
            200..=299 => Ok(()),
            407 => Err(Failure::new(
                "PROXY_AUTH_REQUIRED",
                "proxy requires authentication (407); authenticated proxies are not supported",
            )),
            s => Err(Failure::new(
                "PROXY_CONNECT_REJECTED",
                format!("proxy answered CONNECT with HTTP {s}"),
            )),
        }
    };
    match tokio::time::timeout(limit, exchange).await {
        Err(_) => Err(Failure::new(
            "PROXY_TIMEOUT",
            "CONNECT response exceeded deadline",
        )),
        Ok(Err(e)) => Err(e),
        Ok(Ok(())) => Ok((stream, tcp_ms, start.elapsed().as_secs_f64() * 1000.)),
    }
}

static SESSION: std::sync::OnceLock<ProxyChoice> = std::sync::OnceLock::new();
/// Dashboard-wide route chosen at launch with `ui --proxy`.
pub fn set_session(choice: ProxyChoice) {
    let _ = SESSION.set(choice);
}
pub fn session() -> ProxyChoice {
    SESSION.get().cloned().unwrap_or_default()
}
/// Short header label: DIRECT, or PROXY with its source.
pub fn session_label() -> String {
    match session() {
        ProxyChoice::Direct => "DIRECT".into(),
        other => format!("PROXY {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_choices_and_rejects_secrets() {
        assert_eq!(
            "direct".parse::<ProxyChoice>().unwrap(),
            ProxyChoice::Direct
        );
        assert_eq!("ENV".parse::<ProxyChoice>().unwrap(), ProxyChoice::Env);
        assert_eq!(
            "winhttp".parse::<ProxyChoice>().unwrap(),
            ProxyChoice::System
        );
        let e = Endpoint::parse("http://Proxy.Example:8080/").unwrap();
        assert_eq!((e.host.as_str(), e.port), ("proxy.example", 8080));
        assert_eq!(
            Endpoint::parse("[2001:db8::1]:3128").unwrap().to_string(),
            "http://[2001:db8::1]:3128"
        );
        for bad in [
            "http://user:pw@proxy:8080",
            "https://proxy:443",
            "proxy",
            "proxy:0",
            "http://proxy:8080/path",
            "socks5://p:1080",
            "proxy:80\r\nX: y",
        ] {
            assert!(Endpoint::parse(bad).is_err(), "{bad}");
        }
    }
    #[test]
    fn bypass_rules() {
        let plan = Plan {
            source: "environment".into(),
            endpoint: Some(Endpoint::parse("proxy:8080").unwrap()),
            bypass: vec!["corp.example".into(), "*.internal".into(), ".lan".into()],
            bypass_local: true,
        };
        assert!(plan.route("login.microsoftonline.com").is_some());
        assert!(plan.route("corp.example").is_none());
        assert!(plan.route("a.corp.example").is_none());
        assert!(plan.route("notcorp.example").is_some());
        assert!(plan.route("db.internal").is_none());
        assert!(plan.route("host.lan").is_none());
        assert!(plan.route("intranet").is_none());
        let all = Plan {
            bypass: vec!["*".into()],
            ..plan.clone()
        };
        assert!(all.route("anything.example").is_none());
        assert!(Plan::default().route("x.example").is_none());
    }
    #[test]
    fn winhttp_output() {
        let direct = parse_winhttp(
            "Current WinHTTP proxy settings:\n\n    Direct access (no proxy server).\n",
        );
        assert!(direct.endpoint.is_none());
        let p = parse_winhttp(
            "Current WinHTTP proxy settings:\n\n    Proxy Server(s) :  http=web:80;https=secure.example:8443\n    Bypass List     :  *.corp.example;<local>\n",
        );
        assert_eq!(
            p.endpoint.unwrap().to_string(),
            "http://secure.example:8443"
        );
        assert_eq!(p.bypass, vec!["*.corp.example"]);
        assert!(p.bypass_local);
        let single = parse_winhttp(
            "    Proxy Server(s) :  proxy.example:3128\n    Bypass List     :  (none)\n",
        );
        assert_eq!(single.endpoint.unwrap().port, 3128);
        assert!(single.bypass.is_empty());
    }
    #[test]
    fn info_never_exports_values() {
        let info = describe(&Plan {
            source: "explicit".into(),
            endpoint: Some(Endpoint::parse("proxy.example:8080").unwrap()),
            ..Default::default()
        });
        assert_eq!(info.proxy.as_deref(), Some("http://proxy.example:8080"));
        assert!(info.note.contains("CONNECT"));
    }
}
