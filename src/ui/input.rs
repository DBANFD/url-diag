//! Keyboard and text-input handling for the dashboard.
use super::*;
impl App {
    pub(super) fn accept_input(&mut self, field: &str, value: &str) -> Result<()> {
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
    pub(super) fn key(&mut self, key: KeyCode) -> bool {
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
