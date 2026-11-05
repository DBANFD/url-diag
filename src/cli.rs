use anyhow::{Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::{net::IpAddr, path::PathBuf, time::Duration};

#[derive(Parser, Debug)]
#[command(
    version,
    about = "Direct DNS/TCP/verified TLS connectivity diagnostics"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}
#[derive(Subcommand, Debug)]
pub enum Command {
    /// List service groups including IP-only source coverage gaps.
    Groups,
    /// Launch the interactive terminal dashboard.
    Ui,
    /// List the bundled service URL feed catalogue.
    Feeds {
        #[arg(long, default_value = "")]
        filter: String,
    },
    /// Download a service URL feed and test its concrete root-host entries.
    Edl {
        #[arg(long)]
        feed: String,
        #[command(flatten)]
        options: Options,
    },
    Test {
        #[arg(value_parser = hostname)]
        host: String,
        #[command(flatten)]
        options: Options,
    },
    Profile {
        #[arg(value_enum)]
        name: Profile,
        #[command(flatten)]
        options: Options,
        #[arg(long, value_parser = hostname)]
        tenant_host: Option<String>,
        #[arg(long)]
        config: Option<PathBuf>,
    },
}
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Profile {
    Custom,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Mode {
    Dns,
    Tcp,
    Tls,
    Https,
}
#[derive(Args, Clone, Debug)]
pub struct Options {
    /// Repeat-test preset; sets mode/count/interval/timeout. Runtime includes probe time.
    #[arg(long, value_enum, conflicts_with_all = ["count", "interval", "timeout", "mode", "https"])]
    pub preset: Option<Preset>,
    /// Append each completed DNS result/attempt to a new JSONL evidence file.
    #[arg(long)]
    pub journal: Option<PathBuf>,
    /// Use HEAD / (the default); retained for scripting compatibility.
    #[arg(long)]
    pub generic_http: bool,
    #[arg(long, value_enum, default_value = "tls")]
    pub mode: Mode,
    #[arg(long, default_value_t = 443, value_parser = clap::value_parser!(u16).range(1..))]
    pub port: u16,
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u16).range(1..=1000))]
    pub count: u16,
    #[arg(long, default_value = "1s", value_parser = duration)]
    pub interval: Duration,
    #[arg(long, default_value = "10s", value_parser = positive_duration)]
    pub timeout: Duration,
    #[arg(long, default_value_t = 4, value_parser = clap::value_parser!(u16).range(1..=64))]
    pub concurrency: u16,
    #[arg(long)]
    pub resolve_ip: Option<IpAddr>,
    #[arg(long)]
    pub output: Option<PathBuf>,
    #[arg(long)]
    pub csv: Option<PathBuf>,
    /// Perform a HTTP/1.1 root probe after verified TLS.
    #[arg(long)]
    pub https: bool,
}
impl Options {
    pub fn apply_preset(&mut self, preset: Preset) {
        let (mode, count, interval) = match preset {
            Preset::Quick => (Mode::Https, 3, 1),
            Preset::TlsSoak => (Mode::Tls, 100, 2),
            Preset::Extended => (Mode::Https, 300, 5),
            Preset::Overnight => (Mode::Https, 1000, 30),
        };
        self.mode = mode;
        self.https = false;
        self.count = count;
        self.interval = Duration::from_secs(interval);
        self.timeout = Duration::from_secs(15);
        self.preset = None;
    }
    pub fn effective_mode(&self) -> Mode {
        if self.https { Mode::Https } else { self.mode }
    }
}
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Preset {
    Quick,
    TlsSoak,
    Extended,
    Overnight,
}

fn duration(s: &str) -> Result<Duration, String> {
    let d = humantime::parse_duration(s).map_err(|e| e.to_string())?;
    if d > Duration::from_secs(3600) {
        return Err("maximum duration is 1h".into());
    }
    Ok(d)
}
fn positive_duration(s: &str) -> Result<Duration, String> {
    let d = duration(s)?;
    if d.is_zero() {
        return Err("timeout must be positive".into());
    }
    Ok(d)
}
pub fn hostname(s: &str) -> Result<String, String> {
    let h = s.trim_end_matches('.');
    if h.is_empty()
        || h.len() > 253
        || h.parse::<IpAddr>().is_ok()
        || !h.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(
            "expected a DNS hostname, without URL, wildcard, port, path or credentials".into(),
        );
    }
    Ok(h.to_ascii_lowercase())
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointFile {
    endpoints: Vec<String>,
}
pub fn targets(
    name: Profile,
    tenant: Option<String>,
    config: Option<PathBuf>,
) -> Result<Vec<String>> {
    let mut hosts = if let Some(path) = config {
        let bytes = std::fs::read(path)?;
        if bytes.len() > 1024 * 1024 {
            bail!("configuration exceeds 1 MiB");
        }
        serde_json::from_slice::<EndpointFile>(&bytes)?.endpoints
    } else {
        match name {
            Profile::Custom => Vec::new(),
        }
    };
    if let Some(h) = tenant {
        hosts.push(h);
    }
    if hosts.is_empty() || hosts.len() > 256 {
        bail!("provide 1..256 concrete hosts using --config or --tenant-host");
    }
    let mut out = Vec::new();
    for h in hosts {
        let h = hostname(&h).map_err(anyhow::Error::msg)?;
        if !out.contains(&h) {
            out.push(h);
        }
    }
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_credentials_and_injection() {
        for h in [
            "https://example.com",
            "user:secret@host",
            "*.example.com",
            "host\r\nX: a",
            "127.0.0.1",
            "-bad.com",
        ] {
            assert!(hostname(h).is_err());
        }
        assert_eq!(hostname("EXAMPLE.com.").unwrap(), "example.com");
    }
    #[test]
    fn limits() {
        assert!(Cli::try_parse_from(["d", "test", "example.com", "--count", "1001"]).is_err());
        assert!(Cli::try_parse_from(["d", "test", "example.com", "--timeout", "0s"]).is_err());
        assert!(Cli::try_parse_from(["d", "test", "example.com", "--concurrency", "0"]).is_err());
    }
}
