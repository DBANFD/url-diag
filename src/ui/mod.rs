//! Terminal dashboard: state and event loop here, keys in `input`, drawing in `render`.
use crate::{
    catalog,
    cli::{Mode, Options, Preset},
    edl::{self, FeedSnapshot},
    reporting::{self, Attempt, Report},
    runner::{self, Progress},
};
use anyhow::{Result, ensure};
use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::{
    Frame,
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    widgets::{
        Block, Borders, List, ListState, Paragraph, Row, Sparkline, Table, TableState, Wrap,
    },
};
use std::{collections::BTreeSet, io::IsTerminal, time::Duration};
use tokio::{sync::mpsc, task::JoinHandle};

mod input;
mod render;
use render::*;
#[derive(Clone, Copy, PartialEq)]
enum Page {
    Home,
    Groups,
    Feeds,
    Targets,
    Setup,
    Running,
    Results,
}
struct App {
    page: Page,
    cursor: usize,
    filter: String,
    feeds: Vec<String>,
    hosts: Vec<String>,
    selected: BTreeSet<usize>,
    feed: Option<FeedSnapshot>,
    options: Options,
    status: String,
    input: Option<(String, String)>,
    excluded: bool,
    details: bool,
    attempts: Vec<Attempt>,
    report: Option<Report>,
    rx: Option<mpsc::UnboundedReceiver<Progress>>,
    job: Option<JoinHandle<Result<Report>>>,
    download: Option<JoinHandle<Result<FeedSnapshot>>>,
}
impl App {
    fn new() -> Self {
        let cli = crate::cli::Cli::parse_from([
            "url-diag",
            "test",
            "service.example",
            "--mode",
            "https",
            "--count",
            "3",
        ]);
        let crate::cli::Command::Test { mut options, .. } = cli.command.unwrap() else {
            unreachable!()
        };
        options.proxy = crate::proxy::session();
        Self {
            page: Page::Home,
            cursor: 0,
            filter: String::new(),
            feeds: edl::catalog(""),
            hosts: vec![],
            selected: BTreeSet::new(),
            feed: None,
            options,
            status: format!(
                "Choose a service group or custom hostname. Probes use {} connections.",
                crate::proxy::session_label()
            ),
            input: None,
            excluded: false,
            details: false,
            attempts: vec![],
            report: None,
            rx: None,
            job: None,
            download: None,
        }
    }
    fn rows(&self) -> Vec<String> {
        match self.page {
            Page::Home => vec![
                "Browse service groups (including source coverage gaps)".into(),
                "Browse all non-Microsoft URL feeds".into(),
                "Custom service / tenant hostname".into(),
                "Quit".into(),
            ],
            Page::Groups => catalog::groups()
                .iter()
                .map(|g| {
                    format!(
                        "{} - {} URL feeds{}",
                        g.name,
                        g.url_feeds,
                        if g.url_feeds == 0 {
                            " | IP-only source; Enter adds a custom hostname"
                        } else {
                            ""
                        }
                    )
                })
                .collect(),
            Page::Feeds => self.feeds.iter().map(|u| catalog::label(u)).collect(),
            Page::Targets if self.excluded => self
                .feed
                .as_ref()
                .map(|f| {
                    f.skipped
                        .iter()
                        .map(|s| format!("{} - {}", s.entry, s.reason))
                        .collect()
                })
                .unwrap_or_default(),
            Page::Targets => self
                .hosts
                .iter()
                .enumerate()
                .map(|(i, h)| {
                    format!(
                        "[{}] {h}",
                        if self.selected.contains(&i) { "x" } else { " " }
                    )
                })
                .collect(),
            Page::Setup => vec![
                format!("Mode: {:?} (Enter cycles)", self.options.mode),
                format!("Iterations: {} [1..1000]", self.options.count),
                format!(
                    "Delay between rounds: {} seconds [0..3600]",
                    self.options.interval.as_secs()
                ),
                format!(
                    "Stage timeout: {} seconds [1..3600]",
                    self.options.timeout.as_secs()
                ),
                format!("Port: {} [1..65535]", self.options.port),
                format!("Concurrent probes: {} [1..64]", self.options.concurrency),
                format!(
                    "START - {} hosts × {} rounds | direct | HEAD /",
                    self.selected.len(),
                    self.options.count
                ),
            ],
            _ => vec![],
        }
    }
    fn count(&self) -> usize {
        if matches!(self.page, Page::Running | Page::Results) {
            self.attempts.len()
        } else {
            self.rows().len()
        }
    }
    fn set_hosts(&mut self, hosts: Vec<String>) {
        self.hosts = hosts;
        self.selected = (0..self.hosts.len()).collect();
        self.page = Page::Targets;
        self.cursor = 0;
        self.excluded = false;
    }
    fn start(&mut self) -> Result<()> {
        let hosts: Vec<_> = self
            .selected
            .iter()
            .filter_map(|i| self.hosts.get(*i).cloned())
            .collect();
        ensure!(!hosts.is_empty(), "Select at least one concrete hostname");
        std::fs::create_dir_all("results")?;
        let mut options = self.options.clone();
        options.journal = Some(
            format!(
                "results/attempts-{}.jsonl",
                chrono::Utc::now().format("%Y%m%dT%H%M%S%.9fZ")
            )
            .into(),
        );
        let (tx, rx) = mpsc::unbounded_channel();
        self.job = Some(tokio::spawn(async move {
            runner::run_observed(hosts, &options, |p| {
                let _ = tx.send(p);
            })
            .await
        }));
        self.rx = Some(rx);
        self.attempts.clear();
        self.report = None;
        self.details = false;
        self.cursor = 0;
        self.page = Page::Running;
        self.status =
            "Running. Completed attempts are journaled under results/. Esc cancels.".into();
        Ok(())
    }
    async fn update(&mut self) {
        if let Some(rx) = &mut self.rx {
            while let Ok(p) = rx.try_recv() {
                match p {
                    Progress::Status(s) => self.status = s,
                    Progress::Attempt(a) => self.attempts.push(*a),
                }
            }
        }
        if self.job.as_ref().is_some_and(|j| j.is_finished()) {
            match self
                .job
                .take()
                .unwrap()
                .await
                .map_err(anyhow::Error::from)
                .and_then(|r| r)
            {
                Ok(mut r) => {
                    r.source_feed = self.feed.clone();
                    self.attempts = r.attempts.clone();
                    self.report = Some(r);
                    self.status="Completed. S exports JSON/CSV. HTTP errors are application responses, not transport failures.".into();
                }
                Err(e) => {
                    self.status = format!(
                        "INCOMPLETE: {e:#}. Completed journal records remain under results/."
                    )
                }
            }
            self.page = Page::Results;
        }
        if self.download.as_ref().is_some_and(|j| j.is_finished()) {
            match self.download.take().unwrap().await {
                Ok(Ok(f)) => {
                    let hosts = f.targets.clone();
                    self.status = format!(
                        "{} hosts, {} excluded entries. X shows exclusions; review selection before testing.",
                        hosts.len(),
                        f.skipped.len()
                    );
                    self.feed = Some(f);
                    self.set_hosts(hosts);
                }
                e => self.status = format!("Feed download failed: {e:?}"),
            }
        }
    }
    fn save(&mut self) -> Result<()> {
        let r = self.report.as_ref().ok_or_else(|| {
            anyhow::anyhow!("No final report; completed records remain in results/attempts-*.jsonl")
        })?;
        let stem = format!(
            "results/url-diag-{}",
            chrono::Utc::now().format("%Y%m%dT%H%M%S%.9fZ")
        );
        reporting::export(
            r,
            Some(std::path::Path::new(&format!("{stem}.json"))),
            Some(std::path::Path::new(&format!("{stem}.csv"))),
        )?;
        reporting::export_html(r, std::path::Path::new(&format!("{stem}.html")))?;
        self.status = format!("Saved {stem}.json, .csv and .html");
        Ok(())
    }
}
struct Restore;
impl Drop for Restore {
    fn drop(&mut self) {
        ratatui::restore();
    }
}

pub async fn run(proxy: crate::proxy::ProxyChoice) -> Result<bool> {
    crate::proxy::plan(&proxy).map_err(anyhow::Error::msg)?;
    crate::proxy::set_session(proxy);
    ensure!(
        std::io::stdin().is_terminal() && std::io::stdout().is_terminal(),
        "Interactive mode needs a terminal. Run url-diag --help for scripted commands."
    );
    let mut terminal = ratatui::try_init()?;
    let _restore = Restore;
    let mut app = App::new();
    loop {
        app.update().await;
        terminal.draw(|f| draw(f, &app))?;
        if event::poll(Duration::from_millis(50))?
            && let Event::Key(k) = event::read()?
            && k.kind == KeyEventKind::Press
            && ((k.modifiers.contains(event::KeyModifiers::CONTROL)
                && k.code == KeyCode::Char('c'))
                || app.key(k.code))
        {
            break;
        }
        tokio::task::yield_now().await;
    }
    if let Some(job) = app.job {
        job.abort();
    }
    if let Some(job) = app.download {
        job.abort();
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn completed_results_have_explicit_colored_outcomes() {
        let mut a = App::new();
        a.page = Page::Results;
        let mut attempt = Attempt::new("fixture.example".into(), None, 443, 1);
        attempt.success = true;
        a.attempts.push(attempt);
        a.report = Some(Report {
            source_feed: None,
            schema_version: 2,
            tool_version: "fixture".into(),
            started_at: "start".into(),
            completed_at: "end".into(),
            platform: "fixture".into(),
            mode: "dns".into(),
            warnings: vec![],
            proxy: crate::proxy::detect(),
            dns: vec![],
            summaries: Default::default(),
            attempts: a.attempts.clone(),
        });
        for (success, label, color) in [(true, "PASS", Color::Green), (false, "FAIL", Color::Red)] {
            a.attempts[0].success = success;
            let mut t = ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
            t.draw(|f| draw(f, &a)).unwrap();
            let buffer = t.backend().buffer();
            let text: String = buffer.content.iter().map(|c| c.symbol()).collect();
            assert!(text.contains(label));
            assert!(
                buffer
                    .content
                    .iter()
                    .any(|c| c.symbol() == &label[..1] && c.fg == color)
            );
        }
    }
    #[test]
    fn menus_selection_and_bounds() {
        let mut a = App::new();
        a.key(KeyCode::Enter);
        assert!(a.page == Page::Groups);
        a.cursor = catalog::groups()
            .iter()
            .position(|g| g.id == "aws")
            .unwrap();
        a.key(KeyCode::Enter);
        assert!(a.input.is_some());
        assert!(a.status.contains("IP lists only"));
        a.key(KeyCode::Esc);
        a.accept_input("hostname", "tenant.example").unwrap();
        assert_eq!(a.hosts, vec!["tenant.example"]);
        a.key(KeyCode::Char('a'));
        a.key(KeyCode::Enter);
        assert!(a.page == Page::Targets);
        a.key(KeyCode::Char(' '));
        a.key(KeyCode::Enter);
        assert!(a.page == Page::Setup);
        assert!(a.accept_input("iterations", "1001").is_err());
        assert!(a.accept_input("timeout", "0").is_err());
        a.key(KeyCode::Char('4'));
        assert_eq!(a.options.count, 1000);
        a.key(KeyCode::Char('2'));
        assert_eq!(a.options.mode, Mode::Tls);
    }
    #[test]
    fn rendering_keeps_incomplete_distinct_from_pass() {
        let mut a = App::new();
        let mut attempt = Attempt::new(
            "fixture.example".into(),
            Some("127.0.0.1".parse().unwrap()),
            443,
            1,
        );
        attempt.success = true;
        a.attempts.push(attempt);
        for (w, h) in [(40, 12), (80, 24), (140, 40)] {
            let mut t = ratatui::Terminal::new(ratatui::backend::TestBackend::new(w, h)).unwrap();
            for page in [
                Page::Home,
                Page::Groups,
                Page::Feeds,
                Page::Targets,
                Page::Setup,
                Page::Running,
                Page::Results,
            ] {
                a.page = page;
                t.draw(|f| draw(f, &a)).unwrap();
            }
            let text: String = t
                .backend()
                .buffer()
                .content
                .iter()
                .map(|c| c.symbol())
                .collect();
            assert!(text.contains("INCOMPLETE"));
            assert!(!text.contains("PASS"));
            assert_eq!(verdict(&a).1, Color::Yellow);
        }
    }
    #[tokio::test]
    async fn cancelling_retains_completed_rows_without_final_pass() {
        let mut a = App::new();
        a.page = Page::Running;
        a.job = Some(tokio::spawn(async {
            std::future::pending::<Result<Report>>().await
        }));
        a.attempts
            .push(Attempt::new("fixture.example".into(), None, 443, 1));
        a.key(KeyCode::Esc);
        assert!(a.job.is_none());
        assert_eq!(a.attempts.len(), 1);
        assert_eq!(verdict(&a).0, "INCOMPLETE");
    }
}
