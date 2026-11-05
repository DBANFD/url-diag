use rustls::{ClientConfig, RootCertStore, ServerConfig, pki_types::PrivatePkcs8KeyDer};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use url_diag::{http, tcp, tls};

#[tokio::test]
async fn verified_sni_and_http_403_are_successful_transport() {
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
        assert_eq!(stream.get_ref().1.server_name(), Some("localhost"));
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(stream.read_u8().await.unwrap());
        }
        let request = String::from_utf8(request).unwrap();
        assert!(request.contains(&format!("Host: localhost:{}", address.port())));
        assert!(request.starts_with("HEAD / HTTP/1.1\r\n"));
        stream
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        stream.flush().await.unwrap();
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
    assert!(!tls::certificates(&stream).is_empty());
    assert_eq!(
        http::request(
            &mut stream,
            "localhost",
            address.port(),
            Duration::from_secs(3),
            url_diag::endpoints::probe("service.example", 443, false)
        )
        .await
        .unwrap(),
        403
    );
    server.await.unwrap();
}

#[tokio::test]
async fn untrusted_certificate_is_rejected() {
    let key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![key.cert.der().clone()],
            PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()).into(),
        )
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let _ = tokio_rustls::TlsAcceptor::from(Arc::new(server_config))
            .accept(socket)
            .await;
    });
    let cfg = ClientConfig::builder()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    let socket = tcp::connect(address, Duration::from_secs(3)).await.unwrap();
    let err = tls::handshake(socket, "localhost", Arc::new(cfg), Duration::from_secs(3))
        .await
        .unwrap_err();
    assert_eq!(err.code, "TLS_CERTIFICATE_INVALID");
    server.await.unwrap();
}

#[tokio::test]
async fn stalled_tls_is_not_tcp_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let socket = tcp::connect(address, Duration::from_secs(3)).await.unwrap();
    let (_peer, _) = listener.accept().await.unwrap();
    let cfg = ClientConfig::builder()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    let err = tls::handshake(
        socket,
        "localhost",
        Arc::new(cfg),
        Duration::from_millis(50),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, "TLS_TIMEOUT");
}
