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
        let crate::cli::Command::Test { options, .. } = cli.command.unwrap() else {
            unreachable!()
        };
        Self {
            page: Page::Home,
            cursor: 0,
            filter: String::new(),
            feeds: edl::catalog(""),
            hosts: vec![],
            selected: BTreeSet::new(),
            feed: None,
            options,
            status:
                "Choose a service group or custom hostname. Probes are DIRECT; no proxy routing."
                    .into(),
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
        self.status = format!("Saved {stem}.json and .csv");
        Ok(())
    }
    fn accept_input(&mut self, field: &str, value: &str) -> Result<()> {
        match field {
            "filter" => {
                self.filter = value.into();
                self.feeds = edl::catalog(value);
                self.cursor = 0;
            }
            "hostname" => {
                let h = crate::cli::hostname(value).map_err(anyhow::Error::msg)?;
                self.feed = None;
                self.set_hosts(vec![h]);
            }
            _ => {
                let n = value.parse::<u64>()?;
                match field {
                    "iterations" => {
                        ensure!((1..=1000).contains(&n), "Use 1..1000");
                        self.options.count = n as u16;
                    }
                    "delay" => {
                        ensure!(n <= 3600, "Use 0..3600 seconds");
                        self.options.interval = Duration::from_secs(n);
                    }
                    "timeout" => {
                        ensure!((1..=3600).contains(&n), "Use 1..3600 seconds");
                        self.options.timeout = Duration::from_secs(n);
                    }
                    "port" => {
                        ensure!((1..=65535).contains(&n), "Use 1..65535");
                        self.options.port = n as u16;
                    }
                    "concurrency" => {
                        ensure!((1..=64).contains(&n), "Use 1..64");
                        self.options.concurrency = n as u16;
                    }
                    _ => unreachable!(),
                }
            }
        }
        Ok(())
    }
    fn key(&mut self, key: KeyCode) -> bool {
        if let Some((field, mut value)) = self.input.take() {
            match key {
                KeyCode::Esc => return false,
                KeyCode::Enter => {
                    if let Err(e) = self.accept_input(&field, &value) {
                        self.status = format!("Input error: {e}");
                    }
                    return false;
                }
                KeyCode::Backspace => {
                    value.pop();
                }
                KeyCode::Char(c) if !c.is_control() && value.len() < 512 => value.push(c),
                _ => {}
            }
            self.input = Some((field, value));
            return false;
        }
        if self.download.is_some() {
            if key == KeyCode::Esc {
                self.download.take().unwrap().abort();
                self.status = "Feed download cancelled.".into();
            }
            return false;
        }
        let result = (|| -> Result<bool> {
            match key {
                KeyCode::Char('q') => return Ok(true),
                KeyCode::Up => self.cursor = self.cursor.saturating_sub(1),
                KeyCode::Down => {
                    self.cursor = (self.cursor + 1).min(self.count().saturating_sub(1))
                }
                KeyCode::PageUp => self.cursor = self.cursor.saturating_sub(10),
                KeyCode::PageDown => {
                    self.cursor = (self.cursor + 10).min(self.count().saturating_sub(1))
                }
                KeyCode::Esc => {
                    if let Some(job) = self.job.take() {
                        job.abort();
                        self.page = Page::Results;
                        self.status="INCOMPLETE: cancelled. Completed journal records retained; no final report.".into();
                    } else {
                        self.page = Page::Home;
                        self.cursor = 0;
                        self.details = false;
                    }
                }
                KeyCode::Char('/') if self.page == Page::Feeds => {
                    self.input = Some(("filter".into(), String::new()))
                }
                KeyCode::Char('x') if self.page == Page::Targets => {
                    self.excluded = !self.excluded;
                    self.cursor = 0;
                }
                KeyCode::Char('a') if self.page == Page::Targets && !self.excluded => {
                    if self.selected.len() == self.hosts.len() {
                        self.selected.clear();
                    } else {
                        self.selected = (0..self.hosts.len()).collect();
                    }
                }
                KeyCode::Char(' ')
                    if self.page == Page::Targets
                        && !self.excluded
                        && self.cursor < self.hosts.len() =>
                {
                    if !self.selected.remove(&self.cursor) {
                        self.selected.insert(self.cursor);
                    }
                }
                KeyCode::Char('d') if matches!(self.page, Page::Results | Page::Running) => {
                    self.details = !self.details
                }
                KeyCode::Char('s') if self.page == Page::Results => self.save()?,
                KeyCode::Char(c @ '1'..='4') if self.page == Page::Setup => {
                    self.options.apply_preset(match c {
                        '1' => Preset::Quick,
                        '2' => Preset::TlsSoak,
                        '3' => Preset::Extended,
                        _ => Preset::Overnight,
                    });
                    self.status="Preset selected. Review counts and delay before START; wall time includes probes.".into();
                }
                KeyCode::Enter => match self.page {
                    Page::Home => {
                        match self.cursor {
                            0 => self.page = Page::Groups,
                            1 => {
                                self.page = Page::Feeds;
                                self.feeds = edl::catalog("");
                                self.filter.clear();
                            }
                            2 => self.input = Some(("hostname".into(), String::new())),
                            _ => return Ok(true),
                        }
                        self.cursor = 0;
                    }
                    Page::Groups => {
                        if let Some(g) = catalog::groups().get(self.cursor) {
                            if g.url_feeds == 0 {
                                self.input = Some(("hostname".into(), String::new()));
                                self.status = format!(
                                    "{} source supplies IP lists only. Enter a documented service/tenant hostname; CIDRs are not TLS targets.",
                                    g.name
                                );
                            } else {
                                self.feeds = edl::catalog(&format!("/feeds/{}/", g.id));
                                self.filter = g.name.clone();
                                self.page = Page::Feeds;
                                self.cursor = 0;
                            }
                        }
                    }
                    Page::Feeds => {
                        if let Some(url) = self.feeds.get(self.cursor) {
                            let url = url.clone();
                            self.download =
                                Some(tokio::spawn(async move { edl::fetch(&url).await }));
                            self.status =
                                "Downloading feed over direct verified HTTPS; Esc cancels.".into();
                        }
                    }
                    Page::Targets => {
                        ensure!(
                            !self.selected.is_empty(),
                            "Select at least one hostname; excluded patterns cannot be tested"
                        );
                        self.page = Page::Setup;
                        self.cursor = 0;
                    }
                    Page::Setup => match self.cursor {
                        0 => {
                            self.options.mode = match self.options.mode {
                                Mode::Dns => Mode::Tcp,
                                Mode::Tcp => Mode::Tls,
                                Mode::Tls => Mode::Https,
                                Mode::Https => Mode::Dns,
                            }
                        }
                        6 => self.start()?,
                        n => {
                            self.input = Some((
                                ["", "iterations", "delay", "timeout", "port", "concurrency"][n]
                                    .into(),
                                String::new(),
                            ))
                        }
                    },
                    _ => {}
                },
                _ => {}
            }
            Ok(false)
        })();
        match result {
            Ok(quit) => quit,
            Err(e) => {
                self.status = format!("{e:#}");
                false
            }
        }
    }
}
fn safe(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect()
}
fn panel(title: &str) -> Block<'_> {
    Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(Style::default().fg(Color::Cyan))
}
fn verdict(a: &App) -> (&'static str, Color) {
    if a.page == Page::Running {
        ("RUNNING", Color::Cyan)
    } else if a.report.is_none() || a.attempts.is_empty() {
        ("INCOMPLETE", Color::Yellow)
    } else if a.attempts.iter().any(|x| !x.success) {
        ("FAIL - one or more address attempts", Color::Red)
    } else {
        ("PASS - selected transport stages", Color::Green)
    }
}
fn draw(f: &mut Frame, a: &App) {
    let parts = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(3),
        Constraint::Length(5),
    ])
    .split(f.area());
    let (text, color) = if matches!(a.page, Page::Running | Page::Results) {
        let (v, c) = verdict(a);
        (format!("URL DIAG | {v} | DIRECT"), c)
    } else {
        (
            format!(
                "URL DIAG {} | Service connectivity workbench | DIRECT",
                env!("CARGO_PKG_VERSION")
            ),
            Color::Cyan,
        )
    };
    f.render_widget(
        Paragraph::new(text)
            .style(Style::default().fg(color).add_modifier(Modifier::BOLD))
            .block(panel(" URL Diag ")),
        parts[0],
    );
    let help = match a.page {
        Page::Targets => "Space select | A all/none | X exclusions | Enter configure",
        Page::Setup => "Enter edit/start | 1 Quick | 2 TLS soak | 3 Extended | 4 Overnight",
        Page::Running | Page::Results => {
            "Arrows/PgUp/PgDn select | D details | S save | Esc cancel/home"
        }
        Page::Feeds => "/ search groups/regions | Enter download selected feed | Esc home",
        _ => "Arrows select | Enter open | Esc home | Q quit",
    };
    let input = a
        .input
        .as_ref()
        .map(|(k, v)| format!("{k}: {v}_ [Enter accept, Esc cancel]"))
        .unwrap_or_default();
    f.render_widget(
        Paragraph::new(format!("{help}\n{}\n{input}", safe(&a.status)))
            .wrap(Wrap { trim: true })
            .block(panel(" Controls / status ")),
        parts[2],
    );
    if matches!(a.page, Page::Running | Page::Results) {
        draw_results(f, a, parts[1]);
        return;
    }
    let body = if a.page == Page::Feeds || a.page == Page::Groups {
        let split = Layout::vertical([Constraint::Min(2), Constraint::Length(7)]).split(parts[1]);
        let detail = if a.page == Page::Feeds {
            a.feeds
                .get(a.cursor)
                .map(|u| catalog::description(u))
                .unwrap_or_else(|| "No matching URL feeds.".into())
        } else {
            catalog::groups().get(a.cursor).map(|g|format!("{} | {} URL feeds | {} IP feeds in source.\n{}\nIP ranges cannot identify TLS SNI/hostname. For IP-only groups, supply a documented concrete hostname. No IP ranges are expanded or scanned.",g.name,g.url_feeds,g.ip_feeds,g.source)).unwrap_or_default()
        };
        f.render_widget(
            Paragraph::new(detail)
                .wrap(Wrap { trim: true })
                .block(panel(" Category meaning / coverage ")),
            split[1],
        );
        split[0]
    } else {
        parts[1]
    };
    let title = match a.page {
        Page::Home => " Endpoint source ",
        Page::Groups => " Non-Microsoft service groups ",
        Page::Feeds => " URL feeds - / searches ",
        Page::Targets if a.excluded => " Excluded entries - not tested ",
        Page::Targets => " Select concrete hosts ",
        _ => " Test settings - review before START ",
    };
    let mut state = ListState::default().with_selected(Some(a.cursor));
    f.render_stateful_widget(
        List::new(a.rows())
            .block(panel(title))
            .highlight_symbol(" > ")
            .highlight_style(Style::default().fg(Color::Black).bg(Color::Cyan)),
        body,
        &mut state,
    );
}
struct Restore;
impl Drop for Restore {
    fn drop(&mut self) {
        ratatui::restore();
    }
}

pub async fn run() -> Result<bool> {
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

fn draw_results(f: &mut Frame, a: &App, area: ratatui::layout::Rect) {
    if a.details {
        let text=a.attempts.get(a.cursor).map(|x|format!(
            "{}\nIP {:?} | port {} | round {} | {}\nRequest: {} {}\nAssessment: {}\n\n{}\n\nError: {:?}\nTLS {:?} | {:?}\nCertificates:\n{}",
            x.hostname,x.ip,x.port,x.iteration,x.timestamp,x.http_method.as_deref().unwrap_or("not attempted"),x.http_path.as_deref().unwrap_or(""),
            x.assessment,format_args!("{}\n{}",safe(&x.diagnostic_note),crate::endpoints::alternate_address_note(x,&a.attempts)),x.error,x.tls_version,x.cipher,
            x.certificates.iter().map(|c|format!("Subject: {}\nIssuer: {}\nExpires: {}",safe(&c.subject),safe(&c.issuer),safe(&c.expires))).collect::<Vec<_>>().join("\n")
        )).unwrap_or_else(||"No completed attempt selected.".into());
        f.render_widget(
            Paragraph::new(text)
                .wrap(Wrap { trim: true })
                .block(panel(" Evidence / interpretation - d returns to table ")),
            area,
        );
        return;
    }
    let parts = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(3),
        Constraint::Length(if area.height < 24 { 4 } else { 7 }),
        Constraint::Length(3),
    ])
    .split(area);
    let ok = a.attempts.iter().filter(|x| x.success).count();
    let app_errors = a
        .attempts
        .iter()
        .filter(|x| {
            x.http_status.is_some_and(|s| s >= 400) && x.assessment != "known_http_response"
        })
        .count();
    let total = a.attempts.len();
    f.render_widget(
        Paragraph::new(format!(
            "{} | Done {total} | Transport OK {ok} | Failed attempts {} | HTTP review {app_errors} | {:.1}%",
            if a.page == Page::Running {
                "RUNNING"
            } else {
                "FINISHED"
            },
            total - ok,
            if total == 0 {
                0.
            } else {
                100. * ok as f64 / total as f64
            }
        ))
        .block(panel(
            " Overview - HTTP error responses are not transport failures ",
        )),
        parts[0],
    );
    let rows = a.attempts.iter().map(|x| {
        let status = if !x.success {
            x.error
                .as_ref()
                .map(|e| e.code.as_str())
                .unwrap_or("FAIL")
                .to_string()
        } else if x.assessment == "known_http_response" {
            format!("KNOWN {}", x.http_status.unwrap_or_default())
        } else if x.http_status.is_some_and(|s| s >= 400) {
            format!("HTTP {}", x.http_status.unwrap())
        } else {
            "OK".into()
        };
        let color = if !x.success {
            Color::Red
        } else if x.assessment == "known_http_response" {
            Color::Cyan
        } else if x.http_status.is_some_and(|s| s >= 400) {
            Color::Yellow
        } else {
            Color::Green
        };
        let ms = |v: Option<f64>| v.map(|n| format!("{n:.1}")).unwrap_or_else(|| "-".into());
        Row::new(vec![
            x.iteration.to_string(),
            x.hostname.clone(),
            x.ip.map(|n| n.to_string()).unwrap_or_else(|| "DNS".into()),
            ms(x.tcp_ms),
            ms(x.tls_ms),
            x.http_status.map(|n| n.to_string()).unwrap_or_default(),
            format!("{:.1}", x.total_ms),
            status,
        ])
        .style(Style::default().fg(color))
    });
    let mut state = TableState::default().with_selected(Some(a.cursor));
    f.render_stateful_widget(
        Table::new(
            rows,
            [
                Constraint::Length(3),
                Constraint::Percentage(33),
                Constraint::Percentage(23),
                Constraint::Length(8),
                Constraint::Length(8),
                Constraint::Length(5),
                Constraint::Length(9),
                Constraint::Min(10),
            ],
        )
        .header(
            Row::new([
                "#", "Hostname", "IP", "TCP ms", "TLS ms", "HTTP", "Total ms", "Status",
            ])
            .style(Style::default().bg(Color::Gray).fg(Color::Black)),
        )
        .block(panel(" Per-IP attempts "))
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED)),
        parts[1],
        &mut state,
    );
    let details = a
        .attempts
        .get(a.cursor)
        .map(|x| {
            let cert = x
                .certificates
                .first()
                .map(|c| {
                    format!(
                        "Issuer: {} | Expires: {}",
                        safe(&c.issuer),
                        safe(&c.expires)
                    )
                })
                .unwrap_or_default();
            let error = x
                .error
                .as_ref()
                .map(|e| safe(&e.message))
                .unwrap_or_default();
            let rows: Vec<_> = a
                .attempts
                .iter()
                .filter(|v| v.hostname == x.hostname)
                .collect();
            let summary = crate::statistics::summarize(&rows);
            let latency =
                |v: Option<f64>| v.map(|n| format!("{n:.1}")).unwrap_or_else(|| "-".into());
            let stats = format!(
                "{} | OK {:.1}% | min {} / avg {} / max {} / p95 {} ms",
                x.hostname,
                summary.success_percent,
                latency(summary.min_ms),
                latency(summary.average_ms),
                latency(summary.max_ms),
                latency(summary.p95_ms)
            );
            let dns = a
                .report
                .as_ref()
                .and_then(|r| {
                    r.dns
                        .iter()
                        .find(|d| d.hostname == x.hostname && d.iteration == x.iteration)
                })
                .map(|d| format!("DNS {:.1} ms: {:?}", d.duration_ms, d.addresses))
                .unwrap_or_default();
            format!(
                "{stats}\n{}\n{}\n{} | {:?} | {:?}\n{cert}\n{dns}\n{error}",
                safe(&x.diagnostic_note),
                crate::endpoints::alternate_address_note(x, &a.attempts),
                x.timestamp,
                x.tls_version,
                x.cipher
            )
        })
        .unwrap_or_else(|| "Waiting for first completed probe...".into());
    f.render_widget(
        Paragraph::new(details)
            .wrap(Wrap { trim: true })
            .block(panel(" Selected attempt ")),
        parts[2],
    );
    let samples: Vec<u64> = a
        .attempts
        .iter()
        .rev()
        .take(area.width as usize)
        .map(|x| x.total_ms.max(0.) as u64)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    f.render_widget(
        Sparkline::default()
            .data(&samples)
            .style(Style::default().fg(Color::Yellow))
            .block(panel(
                " Recent total latency (ms, includes failed attempts) ",
            )),
        parts[3],
    );
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
