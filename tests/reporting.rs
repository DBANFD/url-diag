use url_diag::{
    reporting::{self, Attempt, Report},
    statistics,
};
#[test]
fn exports_schema_and_preserves_existing_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let json = dir.path().join("report.json");
    let csv = dir.path().join("attempts.csv");
    let mut a = Attempt::new(
        "service.example".into(),
        Some("127.0.0.1".parse().unwrap()),
        443,
        1,
    );
    a.success = true;
    a.total_ms = 10.;
    let attempts = vec![a];
    let r = Report {
        source_feed: None,
        schema_version: 2,
        tool_version: "test".into(),
        started_at: "start".into(),
        completed_at: "end".into(),
        platform: "test".into(),
        mode: "dns_tcp_tls".into(),
        warnings: vec![],
        proxy: url_diag::proxy::detect(),
        dns: vec![],
        summaries: statistics::grouped(&attempts),
        attempts,
    };
    reporting::export(&r, Some(&json), Some(&csv)).unwrap();
    let original = std::fs::read(&json).unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&original).unwrap();
    assert_eq!(parsed["schema_version"], 2);
    assert_eq!(parsed["attempts"][0]["route"], "direct");
    let mut reader = csv::Reader::from_path(csv).unwrap();
    assert_eq!(reader.records().count(), 1);
    assert!(reporting::export(&r, Some(&json), None).is_err());
    assert_eq!(std::fs::read(json).unwrap(), original);
}

#[test]
fn custom_config_is_validated_and_deduplicated() {
    use url_diag::cli::{Profile, targets};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("targets.json");
    std::fs::write(
        &path,
        r#"{"endpoints":["SERVICE.example","service.example"]}"#,
    )
    .unwrap();
    assert_eq!(
        targets(Profile::Custom, None, Some(path.clone())).unwrap(),
        vec!["service.example"]
    );
    std::fs::write(
        &path,
        r#"{"endpoints":["https://user:secret@service.example"]}"#,
    )
    .unwrap();
    assert!(targets(Profile::Custom, None, Some(path)).is_err());
}
