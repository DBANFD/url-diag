//! Dashboard drawing. Reads application state, never changes it.
use super::*;
pub(super) fn safe(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect()
}
pub(super) fn panel(title: &str) -> Block<'_> {
    Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(Style::default().fg(Color::Cyan))
}
pub(super) fn verdict(a: &App) -> (&'static str, Color) {
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
pub(super) fn draw(f: &mut Frame, a: &App) {
    let parts = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(3),
        Constraint::Length(5),
    ])
    .split(f.area());
    let (text, color) = if matches!(a.page, Page::Running | Page::Results) {
        let (v, c) = verdict(a);
        (
            format!("URL DIAG | {v} | {}", crate::proxy::session_label()),
            c,
        )
    } else {
        (
            format!(
                "URL DIAG {} | Service connectivity workbench | {}",
                env!("CARGO_PKG_VERSION"),
                crate::proxy::session_label()
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
pub(super) fn draw_results(f: &mut Frame, a: &App, area: ratatui::layout::Rect) {
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
