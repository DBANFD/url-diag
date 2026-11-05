use serde::Serialize;
#[derive(Serialize)]
pub struct ProxyInfo {
    pub environment_variables_present: Vec<String>,
    pub note: String,
}
pub fn detect() -> ProxyInfo {
    // Intentionally export variable names only, never values or NO_PROXY contents.
    let names = [
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "https_proxy",
        "http_proxy",
        "all_proxy",
        "no_proxy",
    ];
    ProxyInfo {environment_variables_present:names.iter().filter(|n|std::env::var_os(n).is_some()).map(|n|n.to_string()).collect(),
        note:"All probes are DIRECT and ignore proxy variables. This is not the tested application's effective proxy configuration. Windows WinHTTP/PAC detection and proxy routing are not implemented in this MVP.".into()}
}
