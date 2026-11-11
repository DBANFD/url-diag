//! HTTP CONNECT proxy routing. The implementation lives in diag-core; this module
//! adds this tool's User-Agent and wording.
use crate::reporting::Failure;
pub use diag_core::proxy::*;
use std::time::Duration;

const SUBJECT: &str = "the tested application's";
pub fn detect() -> ProxyInfo {
    diag_core::proxy::detect(SUBJECT)
}
pub fn describe(plan: &Plan) -> ProxyInfo {
    diag_core::proxy::describe(plan, SUBJECT)
}
/// Connect to the proxy and open a CONNECT tunnel. Returns the tunnel and the
/// time spent on the proxy TCP connect and the CONNECT exchange.
pub async fn tunnel(
    proxy: &Endpoint,
    host: &str,
    port: u16,
    limit: Duration,
) -> Result<(tokio::net::TcpStream, f64, f64), Failure> {
    diag_core::proxy::tunnel(proxy, host, port, limit, crate::USER_AGENT).await
}
