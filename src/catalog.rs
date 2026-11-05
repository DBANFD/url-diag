//! Reviewed provider groups. Feed hosts are distinct from the services described.
use serde::Deserialize;
use std::sync::OnceLock;
#[derive(Deserialize)]
pub struct Group {
    pub id: String,
    pub name: String,
    pub url_feeds: usize,
    pub ip_feeds: usize,
    pub source: String,
}
pub fn groups() -> &'static [Group] {
    static GROUPS: OnceLock<Vec<Group>> = OnceLock::new();
    GROUPS.get_or_init(|| {
        serde_json::from_str(include_str!("../assets/service-groups.json"))
            .expect("reviewed group registry")
    })
}
pub fn label(url: &str) -> String {
    let parts: Vec<_> = url
        .split("/feeds/")
        .nth(1)
        .unwrap_or(url)
        .trim_end_matches("/url")
        .split('/')
        .collect();
    parts
        .iter()
        .enumerate()
        .map(|(i, s)| {
            if i == 0 {
                return groups()
                    .iter()
                    .find(|g| g.id == *s)
                    .map(|g| g.name.clone())
                    .unwrap_or_else(|| s.to_string());
            }
            match *s {
                "all" | "any" => "All within this scope".into(),
                "eu" => "EU (Europe)".into(),
                "us" => "US (United States)".into(),
                "uk" => "UK (United Kingdom)".into(),
                "au" => "Australia".into(),
                "ww" | "global" => "Global / shared".into(),
                _ => s.replace(['-', '_'], " "),
            }
        })
        .collect::<Vec<_>>()
        .join(" / ")
}
pub fn description(url: &str) -> String {
    format!(
        "{}: published service/region subset. All means all entries within this feed's scope, not every service or tenant. Only concrete HTTPS hostnames are tested. Wildcards, URL paths, HTTP-only entries and IP ranges are listed as excluded. Authentication or unsupported root requests can return HTTP errors even when transport succeeds. This is not a complete tenant allowlist or application-health verdict.",
        label(url)
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn groups_cover_catalog_and_ip_only_gaps() {
        let urls = crate::edl::catalog("");
        assert_eq!(groups().len(), 18);
        assert_eq!(urls.len(), 67);
        for g in groups() {
            assert_eq!(
                g.url_feeds,
                urls.iter()
                    .filter(|u| u.contains(&format!("/feeds/{}/", g.id)))
                    .count()
            );
            assert!(
                !["m365", "azure", "msdefender", "msintune", "github"].contains(&g.id.as_str())
            );
        }
        assert!(
            groups()
                .iter()
                .any(|g| g.id == "aws" && g.url_feeds == 0 && g.ip_feeds > 0)
        );
    }
    #[test]
    fn reject_unknown_and_excluded_feeds() {
        for group in [
            "m365",
            "azure",
            "msdefender",
            "msintune",
            "github",
            "invented",
        ] {
            assert!(
                crate::edl::validate_url(&format!(
                    "https://saasedl.paloaltonetworks.com/feeds/{group}/all/url"
                ))
                .is_err()
            );
        }
    }
}
