//! Bounded HTTPS feed import. Wildcards are never converted to apex hosts.
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, time::Duration};

pub const CATALOG_SOURCE: &str = "https://docs.paloaltonetworks.com/resources/edl-hosting-service";
pub const CATALOG_DATE: &str = "2026-11-05";
pub fn catalog(filter: &str) -> Vec<String> {
    let filter = filter.to_ascii_lowercase();
    include_str!("../assets/edl-catalog.txt")
        .lines()
        .filter(|s| {
            s.contains(&filter) || crate::catalog::label(s).to_lowercase().contains(&filter)
        })
        .map(str::to_owned)
        .collect()
}
pub fn validate_url(url: &str) -> Result<()> {
    let u = reqwest::Url::parse(url)?;
    ensure!(
        u.scheme() == "https"
            && u.host_str() == Some("saasedl.paloaltonetworks.com")
            && u.username().is_empty()
            && u.password().is_none()
            && u.port().is_none()
            && u.query().is_none()
            && u.fragment().is_none(),
        "Use an HTTPS URL feed on saasedl.paloaltonetworks.com without credentials, query or fragment"
    );
    ensure!(
        u.path().starts_with("/feeds/")
            && u.path().ends_with("/url")
            && u.path()
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_/-".contains(&b)),
        "Expected a /feeds/.../url feed (IP lists are not TLS hostname targets)"
    );
    ensure!(
        catalog("").iter().any(|known| known == url),
        "Select a reviewed non-Microsoft URL feed from the bundled catalog; arbitrary, Microsoft and IP feeds are not supported"
    );
    Ok(())
}
#[derive(Clone, Debug, Serialize)]
pub struct SkippedEntry {
    pub entry: String,
    pub reason: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct FeedSnapshot {
    pub classification: std::collections::BTreeMap<String, String>,
    pub url: String,
    pub retrieved_at: String,
    pub sha256: String,
    pub catalog_source: String,
    pub targets: Vec<String>,
    pub skipped: Vec<SkippedEntry>,
}
pub fn parse_feed(url: &str, body: &str) -> Result<FeedSnapshot> {
    validate_url(url)?;
    ensure!(body.len() <= 2 * 1024 * 1024, "Feed exceeds 2 MiB");
    let mut targets = BTreeSet::new();
    let mut skipped = Vec::new();
    for line in body.lines() {
        let entry = line.trim();
        if entry.is_empty() || entry.starts_with('#') {
            continue;
        }
        ensure!(
            targets.len() + skipped.len() < 10000,
            "Feed exceeds 10000 entries"
        );
        // Do not echo malformed URL credentials or control codes into the terminal/report.
        let reason =
            if entry.contains('@') || entry.contains('?') || entry.chars().any(char::is_control) {
                Some("malformed or credential-bearing entry")
            } else if entry.contains('*') {
                Some("wildcard requires a concrete tenant/service hostname")
            } else if entry.starts_with("http://") {
                Some("HTTP-only entry; TLS test would not represent this URL")
            } else {
                None
            };
        if let Some(reason) = reason {
            skipped.push(SkippedEntry {
                entry: if entry.contains('@')
                    || entry.contains('?')
                    || entry.chars().any(char::is_control)
                {
                    "[redacted malformed entry]".into()
                } else {
                    entry.into()
                },
                reason: reason.into(),
            });
            continue;
        }
        let candidate = entry
            .strip_prefix("https://")
            .unwrap_or(entry)
            .trim_end_matches('/');
        match crate::cli::hostname(candidate) {
            Ok(h)=>{targets.insert(h);}
            Err(_)=>skipped.push(SkippedEntry{entry:entry.into(),reason:"path, IP range, port or unsupported pattern; root-host probe would not cover it".into()})
        }
    }
    ensure!(
        targets.len() <= 256,
        "Feed has more than 256 concrete hosts; select a narrower feed"
    );
    Ok(FeedSnapshot {
        classification: targets.iter().map(|h| (h.clone(),format!("Listed dependency in {}. Feed membership does not prove domain ownership or application health.",crate::catalog::label(url)))).collect(),
        url: url.into(),
        retrieved_at: chrono::Utc::now().to_rfc3339(),
        sha256: format!("{:x}", Sha256::digest(body.as_bytes())),
        catalog_source: CATALOG_SOURCE.into(),
        targets: targets.into_iter().collect(),
        skipped,
    })
}
pub async fn fetch(url: &str) -> Result<FeedSnapshot> {
    validate_url(url)?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("url-diag/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let mut response = client
        .get(url)
        .send()
        .await
        .context("Feed download failed (direct HTTPS)")?;
    ensure!(
        response.status().is_success(),
        "Feed server returned HTTP {}",
        response.status()
    );
    if response
        .content_length()
        .is_some_and(|n| n > 2 * 1024 * 1024)
    {
        bail!("Feed exceeds 2 MiB");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len() + chunk.len() <= 2 * 1024 * 1024,
            "Feed exceeds 2 MiB"
        );
        bytes.extend_from_slice(&chunk);
    }
    parse_feed(
        url,
        std::str::from_utf8(&bytes).context("Feed is not UTF-8")?,
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    const URL: &str = "https://saasedl.paloaltonetworks.com/feeds/androidenterprise/all/url";
    #[test]
    fn patterns_never_become_false_targets() {
        let f=parse_feed(URL,"*.example.com/\nexample.com/\nEXAMPLE.com/\nhttps://ok.example/\npath.example/api/\n10.0.0.0/8\nhttp://plain.example/\nhttps://user:secret@host/\n").unwrap();
        assert_eq!(f.targets, vec!["example.com", "ok.example"]);
        assert_eq!(f.skipped.len(), 5);
        assert!(!serde_json::to_string(&f).unwrap().contains("secret"));
    }
    #[test]
    fn rejects_wrong_origin_and_ip_feeds() {
        for url in [
            "https://saasedl.paloaltonetworks.com.evil.test/feeds/a/url",
            "http://saasedl.paloaltonetworks.com/feeds/a/url",
            "https://saasedl.paloaltonetworks.com/feeds/a/ipv4",
        ] {
            assert!(validate_url(url).is_err());
        }
        assert!(catalog("Microsoft").is_empty());
        for url in catalog("") {
            validate_url(&url).unwrap();
        }
    }
    #[test]
    fn bounds_and_url_variants_do_not_bypass_catalog() {
        for suffix in ["?token=secret", "#fragment", "/", "%2f"] {
            assert!(validate_url(&format!("{URL}{suffix}")).is_err());
        }
        assert!(parse_feed(URL, &"a".repeat(2 * 1024 * 1024 + 1)).is_err());
        let many = (0..257)
            .map(|i| format!("host{i}.example"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(parse_feed(URL, &many).is_err());
    }
}
