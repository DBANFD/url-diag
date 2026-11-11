//! One HTTP/1.1 request over an established TLS stream. The implementation lives in
//! diag-core; this module supplies this tool's User-Agent and probe plan.
use crate::{reporting::Failure, tls::Stream};
pub use diag_core::http::{location, parse_status};
use std::time::Duration;
pub async fn head(s: &mut Stream, host: &str, port: u16, limit: Duration) -> Result<u16, Failure> {
    request(s, host, port, limit, crate::endpoints::generic()).await
}
pub async fn request(
    s: &mut Stream,
    host: &str,
    port: u16,
    limit: Duration,
    plan: crate::endpoints::Probe,
) -> Result<u16, Failure> {
    request_full(s, host, port, limit, plan)
        .await
        .map(|(status, _)| status)
}
/// Status plus a sanitized Location header (3xx only; query and fragment removed).
pub async fn request_full(
    s: &mut Stream,
    host: &str,
    port: u16,
    limit: Duration,
    plan: crate::endpoints::Probe,
) -> Result<(u16, Option<String>), Failure> {
    let request = diag_core::http::Request {
        method: plan.method,
        path: &plan.path,
        user_agent: crate::USER_AGENT,
    };
    diag_core::http::request(s, host, port, limit, request).await
}
