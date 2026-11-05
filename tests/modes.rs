use clap::Parser;
use url_diag::{
    cli::{Cli, Command},
    runner,
};

#[test]
fn only_service_testing_commands_are_exposed() {
    for command in ["defender", "analyzer", "mde-check", "firewall", "collect"] {
        assert!(Cli::try_parse_from(["url-diag", command]).is_err());
    }
    assert!(Cli::try_parse_from(["url-diag", "groups"]).is_ok());
    assert!(Cli::try_parse_from(["url-diag", "feeds"]).is_ok());
}

#[test]
fn presets_are_explicit_and_bounded() {
    use url_diag::cli::{Mode, Preset};
    assert!(
        Cli::try_parse_from([
            "d",
            "test",
            "localhost",
            "--preset",
            "overnight",
            "--count",
            "2"
        ])
        .is_err()
    );
    let mut o = options("dns", 443);
    o.apply_preset(Preset::Overnight);
    assert_eq!(
        (o.count, o.interval.as_secs(), o.mode),
        (1000, 30, Mode::Https)
    );
    o.apply_preset(Preset::TlsSoak);
    assert_eq!((o.count, o.mode), (100, Mode::Tls));
}

#[tokio::test]
async fn journal_retains_completed_evidence_on_cancel_and_refuses_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("evidence.jsonl");
    let mut o = options("dns", 443);
    o.interval = std::time::Duration::from_secs(60);
    o.journal = Some(path.clone());
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        runner::run_observed(vec!["localhost".into()], &o, |e| {
            let _ = tx.send(e);
        })
        .await
    });
    while let Some(event) = rx.recv().await {
        if matches!(event, runner::Progress::Attempt(_)) {
            break;
        }
    }
    task.abort();
    let _ = task.await;
    let before = std::fs::read_to_string(&path).unwrap();
    let records: Vec<serde_json::Value> = before
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(records.iter().any(|r| r["kind"] == "attempt"));
    assert!(!records.iter().any(|r| r["kind"] == "end"));
    let mut o = options("dns", 443);
    o.journal = Some(path.clone());
    assert!(runner::run(vec!["localhost".into()], &o).await.is_err());
    assert_eq!(std::fs::read_to_string(path).unwrap(), before);
}

#[tokio::test]
async fn different_hosts_share_a_bounded_probe_batch() {
    // Both TCP connections must arrive before either gets a TLS response.
    // A sequential host scheduler would time out the first connection.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let first = listener.accept().await.unwrap();
        let second = tokio::time::timeout(std::time::Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();
        drop((first, second));
    });
    let mut o = options("tls", port);
    o.count = 1;
    o.concurrency = 2;
    o.timeout = std::time::Duration::from_secs(5);
    let r = runner::run(vec!["one.example".into(), "two.example".into()], &o)
        .await
        .unwrap();
    server.await.unwrap();
    assert_eq!(r.attempts.len(), 2);
    assert!(r.attempts.iter().all(|a| a.tcp_ms.is_some() && !a.success));
}
fn options(mode: &str, port: u16) -> url_diag::cli::Options {
    let c = Cli::parse_from([
        "d",
        "test",
        "localhost",
        "--mode",
        mode,
        "--resolve-ip",
        "127.0.0.1",
        "--count",
        "2",
        "--interval",
        "0s",
        "--port",
        &port.to_string(),
    ]);
    if let Some(Command::Test { options, .. }) = c.command {
        options
    } else {
        unreachable!()
    }
}
#[tokio::test]
async fn dns_mode_records_override_without_tcp() {
    let r = runner::run(vec!["localhost".into()], &options("dns", 443))
        .await
        .unwrap();
    assert_eq!(r.mode, "dns");
    assert_eq!(r.attempts.len(), 2);
    assert!(
        r.attempts
            .iter()
            .all(|a| a.success && a.tcp_ms.is_none() && a.tls_ms.is_none())
    );
    assert!(r.dns.iter().all(|d| d.source.contains("skipped")));
}
#[tokio::test]
async fn tcp_mode_does_not_attempt_tls() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let r = runner::run(
        vec!["localhost".into()],
        &options("tcp", listener.local_addr().unwrap().port()),
    )
    .await
    .unwrap();
    assert_eq!(r.mode, "dns_tcp");
    assert!(
        r.attempts
            .iter()
            .all(|a| a.success && a.tcp_ms.is_some() && a.tls_ms.is_none())
    );
}
