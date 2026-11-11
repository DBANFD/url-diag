#![forbid(unsafe_code)]
/// Product token sent as User-Agent on HTTP requests and proxy CONNECT.
pub const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));
// DNS, TCP, TLS and statistics come from the shared transport crate.
pub use diag_core::{dns, statistics, tcp, tls};
pub mod catalog;
pub mod cli;
pub mod edl;
pub mod endpoints;
pub mod http;
pub mod proxy;
pub mod reporting;
pub mod runner;
pub mod ui;
