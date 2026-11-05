use crate::{
    cli::{Mode, Options},
    dns, http, proxy,
    reporting::{Attempt, Report},
    statistics, tcp, tls,
};
use futures::{StreamExt, stream};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Instant,
};
async fn probe(
    host: String,
    ip: IpAddr,
    round: u16,
    o: &Options,
    cfg: Option<Arc<rustls::ClientConfig>>,
) -> Attempt {
    let mut a = Attempt::new(host.clone(), Some(ip), o.port, round);
    let total = Instant::now();
    let start = Instant::now();
    let result = tcp::connect(SocketAddr::new(ip, o.port), o.timeout).await;
    a.tcp_ms = Some(start.elapsed().as_secs_f64() * 1000.);
    match result {
        Err(e) => a.error = Some(e),
        Ok(stream) => {
            if o.effective_mode() == Mode::Tcp {
                a.success = true;
                a.total_ms = total.elapsed().as_secs_f64() * 1000.;
                crate::endpoints::assess(&mut a);
                return a;
            }
            let start = Instant::now();
            let result = tls::handshake(
                stream,
                &host,
                cfg.expect("TLS mode initialized trust"),
                o.timeout,
            )
            .await;
            a.tls_ms = Some(start.elapsed().as_secs_f64() * 1000.);
            match result {
                Err(e) => a.error = Some(e),
                Ok(mut s) => {
                    a.tls_version = s.get_ref().1.protocol_version().map(|x| format!("{x:?}"));
                    a.cipher = s
                        .get_ref()
                        .1
                        .negotiated_cipher_suite()
                        .map(|x| format!("{:?}", x.suite()));
                    a.certificates = tls::certificates(&s);
                    a.success = true;
                    if o.effective_mode() == Mode::Https {
                        let start = Instant::now();
                        let plan = crate::endpoints::probe(&host, o.port, o.generic_http);
                        a.http_method = Some(plan.method.into());
                        a.http_path = Some(plan.path.into());
                        match http::request(&mut s, &host, o.port, o.timeout, plan).await {
                            Ok(status) => a.http_status = Some(status),
                            Err(e) => {
                                a.success = false;
                                a.error = Some(e);
                            }
                        }
                        a.http_ms = Some(start.elapsed().as_secs_f64() * 1000.);
                    }
                }
            }
        }
    }
    a.total_ms = total.elapsed().as_secs_f64() * 1000.;
    crate::endpoints::assess(&mut a);
    a
}
pub async fn run(hosts: Vec<String>, o: &Options) -> anyhow::Result<Report> {
    run_observed(hosts, o, |event| {
        if let Progress::Status(s) = event {
            eprintln!("{s}");
        }
    })
    .await
}
#[derive(Clone)]
pub enum Progress {
    Status(String),
    Attempt(Box<Attempt>),
}
pub async fn run_observed(
    hosts: Vec<String>,
    o: &Options,
    emit: impl Fn(Progress),
) -> anyhow::Result<Report> {
    let mut effective = o.clone();
    if let Some(preset) = effective.preset {
        effective.apply_preset(preset);
    }
    let o = &effective;
    let mut journal = o
        .journal
        .as_deref()
        .map(crate::reporting::Journal::create)
        .transpose()?;
    let started_at = chrono::Utc::now().to_rfc3339();
    if let Some(j) = &mut journal {
        j.write("start", serde_json::json!({"started_at":started_at,"hosts":hosts,"mode":format!("{:?}",o.effective_mode()),"count":o.count,"interval_ms":o.interval.as_millis(),"stage_timeout_ms":o.timeout.as_millis(),"concurrency":o.concurrency,"tool_version":env!("CARGO_PKG_VERSION")}))?;
    }
    let (cfg, mut warnings) = if matches!(o.effective_mode(), Mode::Tls | Mode::Https) {
        let (cfg, warnings) = tls::config()?;
        (Some(cfg), warnings)
    } else {
        (None, Vec::new())
    };
    warnings.push("Profiles contain examples only, not a complete service allowlist or proof of application health.".into());
    warnings.push("Native trust roots with rustls validation; OS revocation/AIA behavior is not reproduced. DNS cache may affect repeated results.".into());
    let mut report = Report {
        source_feed: None,
        schema_version: 2,
        tool_version: env!("CARGO_PKG_VERSION").into(),
        started_at,
        completed_at: String::new(),
        platform: std::env::consts::OS.into(),
        mode: match o.effective_mode() {
            Mode::Dns => "dns",
            Mode::Tcp => "dns_tcp",
            Mode::Tls => "dns_tcp_tls",
            Mode::Https => "dns_tcp_tls_https",
        }
        .into(),
        warnings,
        proxy: proxy::detect(),
        dns: Vec::new(),
        attempts: Vec::new(),
        summaries: Default::default(),
    };
    for round in 1..=o.count {
        emit(Progress::Status(format!(
            "Round {round}/{} | resolving {} hosts",
            o.count,
            hosts.len()
        )));
        let mut lookups =
            stream::iter(hosts.clone().into_iter().map(|host| async move {
                dns::resolve(&host, round, o.timeout, o.resolve_ip).await
            }))
            .buffer_unordered(o.concurrency as usize);
        let mut resolved = Vec::new();
        while let Some(d) = lookups.next().await {
            if let Some(j) = &mut journal {
                j.write("dns", &d)?;
            }
            if d.error.is_some() || o.effective_mode() == Mode::Dns {
                let mut a = Attempt::new(d.hostname.clone(), None, o.port, round);
                a.timestamp = d.timestamp.clone();
                a.total_ms = d.duration_ms;
                a.error = d.error.clone();
                a.success = d.error.is_none();
                crate::endpoints::assess(&mut a);
                if let Some(j) = &mut journal {
                    j.write("attempt", &a)?;
                }
                emit(Progress::Attempt(Box::new(a.clone())));
                report.attempts.push(a);
            } else {
                resolved.push((d.hostname.clone(), d.addresses.clone()));
            }
            report.dns.push(d);
        }
        // Interleave addresses from different hosts, sharing one global concurrency limit.
        let max_ips = resolved.iter().map(|(_, ips)| ips.len()).max().unwrap_or(0);
        let jobs: Vec<_> = (0..max_ips)
            .flat_map(|index| {
                resolved
                    .iter()
                    .filter_map(move |(host, ips)| ips.get(index).map(|ip| (host.clone(), *ip)))
            })
            .collect();
        emit(Progress::Status(format!(
            "Round {round}/{} | {} address probes; global concurrency {}",
            o.count,
            jobs.len(),
            o.concurrency
        )));
        let mut pending = stream::iter(
            jobs.into_iter()
                .map(|(host, ip)| probe(host, ip, round, o, cfg.clone())),
        )
        .buffer_unordered(o.concurrency as usize);
        while let Some(a) = pending.next().await {
            if let Some(j) = &mut journal {
                j.write("attempt", &a)?;
            }
            emit(Progress::Attempt(Box::new(a.clone())));
            report.attempts.push(a);
        }
        emit(Progress::Status(format!(
            "Completed round {round}/{}",
            o.count
        )));
        if round < o.count {
            tokio::time::sleep(o.interval).await;
        }
    }
    report
        .attempts
        .sort_by(|a, b| (&a.hostname, a.iteration, a.ip).cmp(&(&b.hostname, b.iteration, b.ip)));
    report.summaries = statistics::grouped(&report.attempts);
    report.completed_at = chrono::Utc::now().to_rfc3339();
    if let Some(j) = &mut journal {
        j.write("end", serde_json::json!({"completed_at":report.completed_at,"attempts":report.attempts.len()}))?;
    }
    Ok(report)
}
