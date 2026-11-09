use clap::Parser;
use rustls::{ClientConfig, RootCertStore, ServerConfig, pki_types::PrivatePkcs8KeyDer};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use url_diag::{
    cli::{Cli, Command, HttpMethod, http_path},
    endpoints, http, tcp, tls,
};

#[test]
fn path_and_method_options() {
    let cli = Cli::try_parse_from([
        "u",
        "test",
        "service.example",
        "--https",
        "--method",
        "get",
        "--path",
        "/api/health?probe=1",
    ])
    .unwrap();
    let Some(Command::Test { options, .. }) = cli.command else {
        panic!()
    };
    assert_eq!(options.method, HttpMethod::Get);
    let plan = endpoints::probe(&options);
    assert_eq!(
        (plan.method, plan.path.as_str()),
        ("GET", "/api/health?probe=1")
    );
    let defaults = Cli::try_parse_from(["u", "test", "service.example"]).unwrap();
    let Some(Command::Test { options, .. }) = defaults.command else {
        panic!()
    };
    let plan = endpoints::probe(&options);
    assert_eq!((plan.method, plan.path.as_str()), ("HEAD", "/"));
    for bad in ["api", "/a b", "/a\r\nX: y", "/a#frag", "/caf\u{e9}"] {
        assert!(http_path(bad).is_err(), "{bad:?}");
    }
    assert!(http_path(&format!("/{}", "a".repeat(2048))).is_err());
    assert!(Cli::try_parse_from(["u", "test", "service.example", "--method", "post"]).is_err());
}

#[tokio::test]
async fn custom_path_is_sent_and_redirect_location_is_sanitized() {
    let key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = key.cert.der().clone();
    let private_key = PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()).into();
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], private_key)
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut stream = tokio_rustls::TlsAcceptor::from(Arc::new(server_config))
            .accept(socket)
            .await
            .unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(stream.read_u8().await.unwrap());
        }
        stream
            .write_all(b"HTTP/1.1 302 Found\r\nLocation: https://login.example/authorize?code=SECRET\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        stream.flush().await.unwrap();
        String::from_utf8(request).unwrap()
    });
    let mut roots = RootCertStore::empty();
    roots.add(cert).unwrap();
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let socket = tcp::connect(address, Duration::from_secs(3)).await.unwrap();
    let mut stream = tls::handshake(
        socket,
        "localhost",
        Arc::new(config),
        Duration::from_secs(3),
    )
    .await
    .unwrap();
    let cli = Cli::try_parse_from([
        "u",
        "test",
        "localhost",
        "--https",
        "--method",
        "get",
        "--path",
        "/status?x=1",
    ])
    .unwrap();
    let Some(Command::Test { options, .. }) = cli.command else {
        panic!()
    };
    let (status, location) = http::request_full(
        &mut stream,
        "localhost",
        address.port(),
        Duration::from_secs(3),
        endpoints::probe(&options),
    )
    .await
    .unwrap();
    assert_eq!(status, 302);
    assert_eq!(location.as_deref(), Some("https://login.example/authorize"));
    let request = server.await.unwrap();
    assert!(
        request.starts_with("GET /status?x=1 HTTP/1.1\r\n"),
        "{request}"
    );

    let mut attempt = url_diag::reporting::Attempt::new("localhost".into(), None, 443, 1);
    attempt.success = true;
    attempt.http_status = Some(status);
    attempt.http_method = Some("GET".into());
    attempt.http_path = Some("/status?x=1".into());
    attempt.redirect_location = location;
    endpoints::assess(&mut attempt);
    assert!(
        attempt
            .diagnostic_note
            .contains("redirect to https://login.example/authorize (not followed)")
    );
    assert!(!attempt.diagnostic_note.contains("SECRET"));
}
