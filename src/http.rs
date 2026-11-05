use crate::{reporting::Failure, tls::Stream};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
pub async fn head(s: &mut Stream, host: &str, port: u16, limit: Duration) -> Result<u16, Failure> {
    request(s, host, port, limit, crate::endpoints::GENERIC).await
}
pub async fn request(
    s: &mut Stream,
    host: &str,
    port: u16,
    limit: Duration,
    plan: crate::endpoints::Probe,
) -> Result<u16, Failure> {
    let work = async {
        let request = format!(
            "{} {} HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: url-diag/{}\r\nConnection: close\r\n\r\n",
            plan.method,
            plan.path,
            env!("CARGO_PKG_VERSION")
        );
        s.write_all(request.as_bytes())
            .await
            .map_err(|e| Failure::new("HTTP_IO", e))?;
        s.flush().await.map_err(|e| Failure::new("HTTP_IO", e))?;
        let mut buf = Vec::new();
        // Bound memory even for hostile or malformed servers.
        loop {
            let b = s.read_u8().await.map_err(|e| Failure::new("HTTP_IO", e))?;
            buf.push(b);
            if buf.ends_with(b"\r\n\r\n") {
                let status = parse_status(&buf)?;
                if (100..200).contains(&status) && status != 101 {
                    buf.clear();
                    continue;
                }
                return Ok(status);
            }
            if buf.len() >= 32768 {
                return Err(Failure::new(
                    "HTTP_HEADERS_TOO_LARGE",
                    "headers exceed 32 KiB",
                ));
            }
        }
    };
    tokio::time::timeout(limit, work)
        .await
        .map_err(|_| Failure::new("HTTP_TIMEOUT", "response headers exceeded deadline"))?
}
pub fn parse_status(buf: &[u8]) -> Result<u16, Failure> {
    let line = buf.split(|b| *b == b'\n').next().unwrap_or_default();
    let text = std::str::from_utf8(line)
        .map_err(|_| Failure::new("HTTP_INVALID_RESPONSE", "invalid status encoding"))?;
    let parts: Vec<_> = text.split_whitespace().collect();
    if parts.len() < 2
        || !matches!(parts[0], "HTTP/1.0" | "HTTP/1.1")
        || parts[1].len() != 3
        || !parts[1].bytes().all(|b| b.is_ascii_digit())
    {
        return Err(Failure::new(
            "HTTP_INVALID_RESPONSE",
            "invalid HTTP/1.x status line",
        ));
    }
    let status = parts[1]
        .parse::<u16>()
        .map_err(|_| Failure::new("HTTP_INVALID_RESPONSE", "invalid status"))?;
    if !(100..=599).contains(&status) {
        return Err(Failure::new(
            "HTTP_INVALID_RESPONSE",
            "status outside 100..599",
        ));
    }
    Ok(status)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn application_errors_are_transport_responses() {
        assert_eq!(
            parse_status(b"HTTP/1.1 403 Forbidden\r\n\r\n").unwrap(),
            403
        );
        assert_eq!(
            parse_status(b"HTTP/1.1 404 Not Found\r\n\r\n").unwrap(),
            404
        );
        assert!(parse_status(b"garbage 200").is_err());
    }
}
