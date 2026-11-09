#![forbid(unsafe_code)]
use clap::Parser;
use url_diag::{
    cli::{Cli, Command, targets},
    reporting, runner,
};
#[tokio::main]
async fn main() -> std::process::ExitCode {
    match execute().await {
        Ok(true) => std::process::ExitCode::SUCCESS,
        Ok(false) => std::process::ExitCode::from(1),
        Err(e) => {
            eprintln!("CONFIG_OR_REPORT_ERROR: {e:#}");
            std::process::ExitCode::from(2)
        }
    }
}
async fn execute() -> anyhow::Result<bool> {
    let cli = Cli::parse();
    let command = match cli.command {
        None => return url_diag::ui::run(Default::default()).await,
        Some(Command::Ui { proxy }) => return url_diag::ui::run(proxy).await,
        Some(command) => command,
    };
    let mut source_feed = None;
    let (hosts, options) = match command {
        Command::Ui { .. } => unreachable!(),
        Command::Groups => {
            for g in url_diag::catalog::groups() {
                println!(
                    "{} ({}) | {} URL feeds | {} IP feeds{}",
                    g.name,
                    g.id,
                    g.url_feeds,
                    g.ip_feeds,
                    if g.url_feeds == 0 {
                        " | IP-only source: supply a documented hostname; IP ranges are not TLS targets"
                    } else {
                        ""
                    }
                );
            }
            return Ok(true);
        }
        Command::Feeds { filter } => {
            for url in url_diag::edl::catalog(&filter) {
                println!(
                    "{}\n  {}\n  {url}\n",
                    url_diag::catalog::label(&url),
                    url_diag::catalog::description(&url)
                );
            }
            return Ok(true);
        }
        Command::Edl { feed, options } => {
            let snapshot = url_diag::edl::fetch(&feed).await?;
            eprintln!(
                "{} concrete hosts; {} entries excluded (wildcards/paths/patterns).",
                snapshot.targets.len(),
                snapshot.skipped.len()
            );
            for x in &snapshot.skipped {
                eprintln!("SKIPPED {}: {}", x.entry, x.reason);
            }
            anyhow::ensure!(
                !snapshot.targets.is_empty(),
                "Feed has no concrete root-host targets"
            );
            let hosts = snapshot.targets.clone();
            source_feed = Some(snapshot);
            (hosts, options)
        }
        Command::Test { host, options } => (
            vec![url_diag::cli::hostname(&host).map_err(anyhow::Error::msg)?],
            options,
        ),
        Command::Profile {
            name,
            options,
            tenant_host,
            config,
        } => (targets(name, tenant_host, config)?, options),
    };
    let mut report = tokio::select! {
        result=runner::run(hosts, &options)=>result?,
        _=tokio::signal::ctrl_c()=>{ eprintln!("INCOMPLETE: cancelled. Completed records are retained only when --journal was specified."); return Ok(false); }
    };
    report.source_feed = source_feed;
    reporting::console(&report);
    reporting::export(&report, options.output.as_deref(), options.csv.as_deref())?;
    if let Some(path) = &options.html {
        reporting::export_html(&report, path)?;
    }
    Ok(report.attempts.iter().all(|a| a.success))
}
