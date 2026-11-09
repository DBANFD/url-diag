use clap::Parser;
use rustls::{ClientConfig, RootCertStore, ServerConfig, pki_types::PrivatePkcs8KeyDer};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use url_diag::{
    cli::{Cli, Command},
    proxy, reporting, runner, tls,
};

/// Minimal CONNECT proxy: answers with `status`, then (on 200) relays to `upstream`.
async fn fake_proxy(
    status: u16,
    upstream: Option<std::net::SocketAddr>,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut client, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(client.read_u8().await.unwrap());
        }
        let reply = format!("HTTP/1.1 {status} Status\r\nContent-Length: 0\r\n\r\n");
        client.write_all(reply.as_bytes()).await.unwrap();
        if status == 200 {
            let mut server = tokio::net::TcpStream::connect(upstream.unwrap())
                .await
                .unwrap();
            let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
        }
        String::from_utf8(request).unwrap()
    });
    (address, task)
}

#[tokio::test]
async fn tunnel_then_verified_tls_through_connect_proxy() {
    let key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = key.cert.der().clone();
    let private_key = PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()).into();
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], private_key)
        .unwrap();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_address = origin.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (socket, _) = origin.accept().await.unwrap();
        let stream = tokio_rustls::TlsAcceptor::from(Arc::new(server_config))
            .accept(socket)
            .await
            .unwrap();
        assert_eq!(stream.get_ref().1.server_name(), Some("localhost"));
    });
    let (proxy_address, proxy_task) = fake_proxy(200, Some(origin_address)).await;
    let endpoint = proxy::Endpoint::parse(&proxy_address.to_string()).unwrap();
    let (stream, tcp_ms, connect_ms) =
        proxy::tunnel(&endpoint, "localhost", 443, Duration::from_secs(3))
            .await
            .unwrap();
    assert!(tcp_ms >= 0. && connect_ms >= 0.);
    let mut roots = RootCertStore::empty();
    roots.add(cert).unwrap();
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let tls_stream = tls::handshake(
        stream,
        "localhost",
        Arc::new(config),
        Duration::from_secs(3),
    )
    .await
    .unwrap();
    assert!(!tls::certificates(&tls_stream).is_empty());
    drop(tls_stream);
    server.await.unwrap();
    let request = proxy_task.await.unwrap();
    assert!(
        request.starts_with("CONNECT localhost:443 HTTP/1.1\r\n"),
        "{request}"
    );
    assert!(request.contains("Host: localhost:443\r\n"));
}

#[tokio::test]
async fn proxy_rejections_are_named_failures() {
    for (status, code) in [
        (407, "PROXY_AUTH_REQUIRED"),
        (403, "PROXY_CONNECT_REJECTED"),
    ] {
        let (address, task) = fake_proxy(status, None).await;
        let endpoint = proxy::Endpoint::parse(&address.to_string()).unwrap();
        let err = proxy::tunnel(&endpoint, "example.invalid", 443, Duration::from_secs(3))
            .await
            .unwrap_err();
        assert_eq!(err.code, code);
        task.await.unwrap();
    }
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = closed.local_addr().unwrap();
    drop(closed);
    let endpoint = proxy::Endpoint::parse(&address.to_string()).unwrap();
    let err = proxy::tunnel(&endpoint, "example.invalid", 443, Duration::from_secs(3))
        .await
        .unwrap_err();
    assert!(err.code.starts_with("PROXY_TCP_"), "{}", err.code);
}

#[tokio::test]
async fn runner_tunnels_names_that_do_not_resolve_locally() {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_address = origin.local_addr().unwrap();
    let accept = tokio::spawn(async move {
        let _ = origin.accept().await.unwrap();
    });
    let (proxy_address, proxy_task) = fake_proxy(200, Some(origin_address)).await;
    let cli = Cli::try_parse_from([
        "url-diag",
        "test",
        "proxied-only.invalid",
        "--mode",
        "tcp",
        "--timeout",
        "3s",
        "--proxy",
        &format!("http://{proxy_address}"),
    ])
    .unwrap();
    let Some(Command::Test { host, options }) = cli.command else {
        panic!("expected test command")
    };
    let report = runner::run_observed(vec![host], &options, |_| {})
        .await
        .unwrap();
    assert_eq!(
        report.attempts.len(),
        1,
        "one tunnelled attempt per host and round"
    );
    let attempt = &report.attempts[0];
    assert!(attempt.success, "{:?}", attempt.error);
    assert_eq!(attempt.ip, None);
    assert_eq!(attempt.route, format!("proxy http://{proxy_address}"));
    assert!(attempt.proxy_connect_ms.is_some());
    assert_eq!(report.proxy.source, "explicit");
    assert!(
        report.dns[0].error.is_some(),
        "local DNS failure is still recorded as evidence"
    );
    assert_eq!(reporting::outcome(&report), "PASS");
    let html = reporting::render_html(&report);
    assert!(html.contains("PROXY http://127.0.0.1"));
    assert!(!html.contains('\u{2014}'));
    accept.await.unwrap();
    assert!(
        proxy_task
            .await
            .unwrap()
            .starts_with("CONNECT proxied-only.invalid:443 ")
    );
}

#[test]
fn html_report_escapes_and_never_overwrites() {
    let cli = Cli::try_parse_from(["d", "test", "example.com", "--html", "x.html"]).unwrap();
    let Some(Command::Test { options, .. }) = cli.command else {
        panic!()
    };
    assert_eq!(
        options.html.as_deref(),
        Some(std::path::Path::new("x.html"))
    );
    let mut attempt = reporting::Attempt::new("<script>.example".into(), None, 443, 1);
    attempt.error = Some(reporting::Failure::new("TCP_REFUSED", "<b>refused</b>"));
    let report = reporting::Report {
        source_feed: None,
        schema_version: 2,
        tool_version: "test".into(),
        started_at: "s".into(),
        completed_at: "c".into(),
        platform: "test".into(),
        mode: "dns_tcp".into(),
        warnings: vec!["<i>note</i>".into()],
        proxy: proxy::detect(),
        dns: vec![],
        attempts: vec![attempt],
        summaries: Default::default(),
    };
    let html = reporting::render_html(&report);
    assert!(
        !html.contains("<script>") && !html.contains("<b>refused") && !html.contains("<i>note")
    );
    assert!(html.contains("&lt;script&gt;.example") && html.contains("FAIL"));
    let dir = std::env::temp_dir().join(format!("dd-html-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("r.html");
    let _ = std::fs::remove_file(&path);
    reporting::export_html(&report, &path).unwrap();
    assert!(reporting::export_html(&report, &path).is_err());
    std::fs::remove_dir_all(&dir).unwrap();
}
