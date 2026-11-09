use crate::reporting::Attempt;
#[derive(Debug, Clone)]
pub struct Probe {
    pub method: &'static str,
    pub path: String,
    pub source: &'static str,
}
pub const GENERIC_METHOD: &str = "HEAD";
pub fn generic() -> Probe {
    Probe {
        method: GENERIC_METHOD,
        path: "/".into(),
        source: "generic root connectivity probe",
    }
}
/// Request plan from the options: HEAD / by default, or the operator's method and path.
pub fn probe(o: &crate::cli::Options) -> Probe {
    if o.method == crate::cli::HttpMethod::Head && o.path == "/" {
        generic()
    } else {
        Probe {
            method: o.method.as_str(),
            path: o.path.clone(),
            source: "operator-selected request path",
        }
    }
}
pub fn failure_guidance(a: &Attempt) -> String {
    let Some(e) = &a.error else {
        return String::new();
    };
    let hint = match e.code.as_str() {
        "DNS_TIMEOUT" => {
            "DNS did not answer before the deadline. Check resolver reachability and repeat; TCP/TLS were not tested."
        }
        "DNS_LOOKUP_FAILED" => {
            "No usable address was resolved. Check the exact name, regional/OS applicability and resolver response. A feed entry or wildcard parent is not necessarily a standalone service hostname; this does not prove the service is offline."
        }
        "TCP_TIMEOUT" => {
            "DNS resolved but this IP/port did not complete TCP before the deadline. Routing, filtering or packet loss are possibilities; the failing component is not established."
        }
        "TCP_REFUSED" => {
            "This IP actively refused the connection. Check the documented port and service endpoint; refusal is not a DNS or certificate error."
        }
        "TCP_UNREACHABLE" => {
            "No route to this IP was available. Compare IPv4 and IPv6: an unavailable address family can fail while another address works."
        }
        "TCP_PERMISSION_DENIED" => {
            "The local OS denied the connection. Review local firewall/security policy and process permissions."
        }
        "TLS_TIMEOUT" => {
            "TCP connected, but TLS negotiation timed out. Check TLS inspection, proxy requirements, packet loss/MTU and repeat. TCP success alone does not establish HTTPS connectivity."
        }
        "TLS_CERTIFICATE_INVALID" => {
            "TLS certificate validation failed. Check hostname, expiry, system time and trust chain; inspection is one possible cause, not proven by this error alone. Verification was not bypassed."
        }
        "TLS_HANDSHAKE_FAILED" => {
            "TCP connected but TLS negotiation failed. Review the raw alert/reset, TLS inspection and route. This app does not reproduce application-specific certificate pinning."
        }
        "HTTP_TIMEOUT" => {
            "TLS validated, but no complete HTTP headers arrived before the deadline. Check the recorded method/path and intermediary/service behavior."
        }
        "HTTP_IO" => {
            "The connection ended or failed while exchanging HTTP after TLS. A generic root/method may not be a service diagnostic; compare the documented request path."
        }
        "PROXY_AUTH_REQUIRED" => {
            "The proxy answered 407 and requires authentication. This app does not send proxy credentials; test with a route that allows unauthenticated CONNECT."
        }
        "PROXY_CONNECT_REJECTED" => {
            "The proxy refused to open a tunnel to this host and port. Check the proxy allowlist or category policy for this destination."
        }
        "PROXY_TIMEOUT" | "PROXY_TCP_TIMEOUT" => {
            "The proxy did not connect or answer CONNECT before the deadline. Check the proxy address, port and reachability."
        }
        code if code.starts_with("PROXY_") => {
            "Connecting to the configured proxy failed. Check the proxy address and port; the target host was not reached."
        }
        _ => {
            "The recorded stage failed for this attempt. Retain the raw error and compare another IP/round; do not infer a service outage from one address probe."
        }
    };
    let family = if a.ip.is_some_and(|ip| ip.is_ipv6()) {
        " This is an IPv6 attempt; inspect IPv4 results before deciding the hostname is unreachable."
    } else {
        ""
    };
    let route = if a.route.starts_with("proxy") {
        format!(
            " Route: {} (HTTP CONNECT). This may still differ from the application's own proxy and pinning context.",
            a.route
        )
    } else {
        " DIRECT route: proxy variables and the application's proxy/pinning context are not used."
            .to_string()
    };
    format!("{hint}{family}{route} No failure is suppressed as expected.")
}
/// Evidence about another working address, without changing the failed attempt.
pub fn alternate_address_note(a: &Attempt, attempts: &[Attempt]) -> &'static str {
    if !a.success
        && attempts.iter().any(|b| {
            b.hostname == a.hostname && b.iteration == a.iteration && b.ip != a.ip && b.success
        })
    {
        "Another IP for this hostname completed the selected stages in the same round. This is an address-specific failure, not total hostname unreachability."
    } else {
        ""
    }
}
pub fn assess(a: &mut Attempt) {
    let (kind, note) = if a.error.is_some() {
        ("transport_failure", failure_guidance(a))
    } else if let Some(status) = a.http_status {
        (
            if status >= 400 {
                "review_http"
            } else {
                "response_received"
            },
            format!(
                "HTTP {status}: HTTPS transport completed{}. This request does not prove application health; authentication, path or service policy may explain the response.",
                a.redirect_location
                    .as_deref()
                    .map(|l| format!(" with a redirect to {l} (not followed)"))
                    .unwrap_or_default()
            ),
        )
    } else {
        (
            "stage_succeeded",
            "Selected diagnostic stages completed; downstream service operation is not asserted."
                .into(),
        )
    };
    a.assessment = kind.into();
    a.diagnostic_note = note;
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn application_errors_do_not_hide_transport_evidence() {
        let mut a = Attempt::new("service.example".into(), None, 443, 1);
        a.success = true;
        a.http_status = Some(403);
        assess(&mut a);
        assert!(a.success);
        assert_eq!(a.assessment, "review_http");
        a.success = false;
        a.error = Some(crate::reporting::Failure::new(
            "TLS_CERTIFICATE_INVALID",
            "fixture",
        ));
        assess(&mut a);
        assert!(!a.success);
        assert_eq!(a.assessment, "transport_failure");
        assert!(a.diagnostic_note.contains("not proven"));
    }
}
