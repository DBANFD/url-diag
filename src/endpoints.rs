use crate::reporting::Attempt;
#[derive(Debug, Clone, Copy)]
pub struct Probe {
    pub method: &'static str,
    pub path: &'static str,
    pub source: &'static str,
}
pub const GENERIC: Probe = Probe {
    method: "HEAD",
    path: "/",
    source: "generic root connectivity probe",
};
pub fn probe(_host: &str, _port: u16, _generic: bool) -> Probe {
    GENERIC
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
        _ => {
            "The recorded stage failed for this attempt. Retain the raw error and compare another IP/round; do not infer a service outage from one address probe."
        }
    };
    let family = if a.ip.is_some_and(|ip| ip.is_ipv6()) {
        " This is an IPv6 attempt; inspect IPv4 results before deciding the hostname is unreachable."
    } else {
        ""
    };
    format!(
        "{hint}{family} DIRECT route: proxy variables and the application's proxy/pinning context are not used. No failure is suppressed as expected."
    )
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
                "HTTP {status}: HTTPS transport completed. This root request does not prove application health; authentication, path or service policy may explain the response."
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
