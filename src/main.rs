//! SSL-Toolkit - SSL/TLS Diagnostic Tool
//!
//! Entry point for the SSL-Toolkit application. Supports interactive prompts,
//! direct CLI output, JSON mode, and quiet mode.

use anyhow::Result;
use chrono::Local;
use console::style;
use ssl_toolkit::cli::Cli;
use ssl_toolkit::config;
use ssl_toolkit::output::{banner, grade, interactive, json, pager, pager::PagerAction, results};
use ssl_toolkit::report::HtmlReport;
use ssl_toolkit::runner::{self, CheckEvent, RunConfig};
use ssl_toolkit::TestResult;
use ssl_toolkit::utils::progress;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    // Parse CLI arguments
    let cli = Cli::parse_args();

    // Load configuration
    let (settings, theme, _messages) = config::load_default_config().unwrap_or_else(|_| {
        (
            config::Settings::default(),
            config::Theme::default(),
            config::Messages::default(),
        )
    });

    let is_interactive = cli.is_interactive();
    let verbose = cli.verbose || is_interactive;

    // Show banner in interactive mode
    if is_interactive && !cli.has_domain() {
        banner::print_banner();
    }

    // Get domain (with retry loop for interactive DNS failure)
    let mut domain = if let Some(d) = cli.normalized_domain() {
        d
    } else if is_interactive {
        interactive::prompt_domain()?
    } else {
        anyhow::bail!("Domain is required. Use --domain or -d to specify, or run without flags for interactive mode.");
    };

    // Get port - prompt in interactive mode if not explicitly set via CLI
    let port = if is_interactive && !cli.port_was_set() {
        interactive::prompt_port(cli.port_or_default())?
    } else {
        cli.port_or_default()
    };

    // DNS Resolution with retry loop for interactive mode
    let target_ips: Vec<IpAddr> = if let Some(ip) = cli.ip {
        if !cli.json && !cli.quiet {
            println!("  {} Using IP override: {}", style("ℹ").cyan(), ip);
        }
        vec![ip]
    } else {
        loop {
            let spinner = progress::create_spinner("Resolving DNS across providers...");
            let dns_results = runner::resolve_dns(&domain, &settings, &|_event| {}).await?;
            spinner.finish_and_clear();

            // Collect all unique IPs
            let mut all_ips: Vec<IpAddr> = dns_results
                .iter()
                .flat_map(|r| r.addresses.iter().copied())
                .collect();
            all_ips.sort();
            all_ips.dedup();

            if all_ips.is_empty() {
                if is_interactive {
                    println!(
                        "  {} No IP addresses found for {}",
                        style("✗").red(),
                        domain
                    );
                    match interactive::prompt_dns_failure(&domain)? {
                        interactive::DnsFailureAction::ManualIp(ip) => {
                            break vec![ip];
                        }
                        interactive::DnsFailureAction::Retry => {
                            domain = interactive::prompt_domain()?;
                            continue;
                        }
                        interactive::DnsFailureAction::Quit => {
                            std::process::exit(0);
                        }
                    }
                } else if cli.json {
                    println!(
                        "{}",
                        serde_json::json!({"error": "DNS resolution failed", "domain": domain})
                    );
                    std::process::exit(2);
                } else if !cli.quiet {
                    println!(
                        "  {} No IP addresses found for {}",
                        style("✗").red(),
                        domain
                    );
                    std::process::exit(2);
                } else {
                    std::process::exit(2);
                }
            }

            // Show DNS results in verbose/interactive mode
            if verbose && !cli.json && !cli.quiet {
                println!();
                println!(
                    "  {} {}",
                    style("✓").green(),
                    style("DNS Resolution Complete").bold()
                );

                let dns_table_data: Vec<(String, bool, String, String)> = dns_results
                    .iter()
                    .map(|r| {
                        (
                            r.provider.clone(),
                            r.is_success(),
                            if r.addresses.is_empty() {
                                r.error.clone().unwrap_or_else(|| "-".to_string())
                            } else {
                                r.addresses
                                    .iter()
                                    .map(|ip| ip.to_string())
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            },
                            format!("{}ms", r.query_time.as_millis()),
                        )
                    })
                    .collect();
                ssl_toolkit::output::tables::print_dns_table(&dns_table_data);
                println!();
            } else if !cli.json && !cli.quiet {
                let successful = dns_results.iter().filter(|r| r.is_success()).count();
                let total = dns_results.len();
                println!(
                    "  {} DNS: {}/{} providers resolved",
                    style("✓").green(),
                    successful,
                    total
                );
            }

            // IP selection - always prompt in interactive mode (allows manual override)
            if is_interactive {
                break interactive::prompt_ip_selection(&all_ips)?;
            } else {
                break all_ips;
            }
        }
    };

    if target_ips.is_empty() {
        anyhow::bail!("No IP addresses selected");
    }

    // Run checks
    let run_config = RunConfig {
        domain: domain.clone(),
        target_ips: target_ips.clone(),
        port,
        settings: settings.clone(),
        skip_whois: cli.skip_whois,
    };

    // Progress callback
    let is_json = cli.json;
    let is_quiet = cli.quiet;
    let on_event = move |event: CheckEvent| {
        if is_json || is_quiet {
            return;
        }
        match event {
            CheckEvent::TcpStarted { .. } => {}
            CheckEvent::TcpComplete { ip, ms } => {
                if !verbose {
                    println!(
                        "  {} TCP: Connected to {} ({:.1}ms)",
                        style("✓").green(),
                        ip,
                        ms
                    );
                }
            }
            CheckEvent::SslComplete { .. } => {}
            CheckEvent::CertComplete { days } => {
                if !verbose {
                    if days < 0 {
                        println!(
                            "  {} Certificate: EXPIRED {} days ago",
                            style("✗").red(),
                            -days
                        );
                    } else {
                        println!(
                            "  {} Certificate: Valid ({} days)",
                            style("✓").green(),
                            days
                        );
                    }
                }
            }
            CheckEvent::ComparisonStarted { current, total, ip } => {
                if verbose {
                    println!(
                        "  {} Comparing certificate ({}/{}) {}",
                        style("…").dim(),
                        current,
                        total,
                        ip
                    );
                }
            }
            CheckEvent::WhoisStarted => {
                if !verbose {
                    // spinner handles this in verbose mode
                }
            }
            CheckEvent::WhoisComplete => {
                if !verbose {
                    println!("  {} WHOIS: Lookup complete", style("✓").green());
                }
            }
            CheckEvent::WhoisSkipped => {
                if !verbose {
                    println!("  {} WHOIS: Skipped", style("ℹ").cyan());
                }
            }
            CheckEvent::Error(msg) => {
                println!("  {} {}", style("✗").red(), msg);
            }
            _ => {}
        }
    };

    let spinner = if !cli.json && !cli.quiet {
        Some(progress::create_spinner("Running checks..."))
    } else {
        None
    };

    // Resolve DNS results for the runner (re-resolve if needed for report data)
    let dns_results = if cli.ip.is_some() {
        vec![]
    } else {
        runner::resolve_dns(&domain, &settings, &|_| {}).await?
    };

    if let Some(s) = &spinner {
        s.finish_and_clear();
    }

    let result = runner::run_checks(run_config, dns_results, &on_event).await;

    match result {
        Ok(run_result) => {
            // Output based on mode
            if cli.json {
                json::print_json(&run_result)?;
            } else if cli.quiet {
                grade::print_grade_quiet(run_result.report.grade);
            } else if verbose {
                // Build full detailed output as a string for paging
                let mut output = String::new();

                let sections: Vec<Option<&TestResult>> = vec![
                    run_result.report.dns_result.as_ref(),
                    run_result.report.tcp_result.as_ref(),
                    run_result.report.ssl_result.as_ref(),
                    run_result.report.certificate_result.as_ref(),
                    run_result.report.whois_result.as_ref(),
                ];

                for section in sections.into_iter().flatten() {
                    output.push_str(&results::format_test_result(section, true));
                }

                // Certificate comparison summary
                if run_result.cert_comparison.entries.len() > 1 {
                    output.push_str(&format!(
                        "  {} {}\n\n",
                        if run_result.cert_comparison.has_differences {
                            style("⚠").yellow()
                        } else {
                            style("✓").green()
                        },
                        run_result.cert_comparison.summary
                    ));
                }

                // Grade
                output.push_str(&grade::format_grade(
                    run_result.report.grade,
                    run_result.report.score,
                ));

                // Recommendations
                let recs = run_result.report.all_recommendations();
                if !recs.is_empty() {
                    output.push_str(&format!(
                        "  {}\n",
                        style("Recommendations:").yellow().bold()
                    ));
                    for rec in &recs {
                        output.push_str(&format!("  {} {}\n", style("→").yellow(), rec));
                    }
                    output.push('\n');
                }

                // Display with pager in interactive mode, or print directly
                if is_interactive {
                    let header = format!(
                        "SSL/TLS Report for {} (port {})",
                        domain, port
                    );

                    // Build save closure that the pager calls inline when 's' is pressed
                    let save_domain = domain.clone();
                    let save_theme = theme.clone();
                    let save_run_result = &run_result;
                    let on_save = move |input: Option<String>| {
                        let default_filename = generate_default_filename(&save_domain);
                        
                        // If input provided, use it. If not, prompt with dialoguer if in prompt mode, or use default.
                        // But now we are using TUI popup mode mainly.
                        // The callback receives `Some(path)` if user typed something, or `None` if they accepted default/empty.
                        // Wait, TUI popup logic: "Enter filename (leave empty for default)".
                        // So if None, we use default. If Some, we use it.
                        // Actually, the closure signature is just a helper.
                        // Let's adapt it.
                        
                        let path = match input {
                            Some(s) if !s.trim().is_empty() => s,
                            _ => default_filename.clone(),
                        };

                        let report = HtmlReport::new(save_theme.clone());
                        let output_path = PathBuf::from(&path);
                        report
                            .generate_from_result(&save_domain, save_run_result, &output_path)
                            .map(|_| Some(path))
                            .map_err(|e| e.to_string())
                    };

                    let action = pager::display_paged(&header, &output, on_save);

                    match action {
                        PagerAction::NewCheck => {
                            let exe = std::env::current_exe()?;
                            let err = exec_process(&exe);
                            anyhow::bail!("Failed to restart: {}", err);
                        }
                        PagerAction::Quit => {}
                    }
                } else {
                    println!();
                    print!("{}", output);
                }
            } else {
                // Compact direct mode
                grade::print_grade_compact(run_result.report.grade, run_result.report.score);
                println!();
            }

            // Report generation (CLI mode with -o flag)
            if let Some(output_path) = &cli.output {
                save_report(
                    &domain,
                    &run_result,
                    &theme,
                    output_path,
                    cli.json,
                    cli.quiet,
                )?;
            }

            // Exit code based on status
            match run_result.report.overall_status() {
                ssl_toolkit::CheckStatus::Fail => std::process::exit(2),
                ssl_toolkit::CheckStatus::Warning => std::process::exit(1),
                ssl_toolkit::CheckStatus::Pass => {}
            }
        }
        Err(e) => {
            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({"error": e.to_string(), "domain": domain})
                );
            } else if !cli.quiet {
                println!("  {} {}", style("✗").red(), e);
            }
            std::process::exit(2);
        }
    }

    Ok(())
}

fn save_report(
    domain: &str,
    run_result: &runner::RunResult,
    theme: &config::Theme,
    output_path: &Path,
    is_json: bool,
    is_quiet: bool,
) -> Result<()> {
    let report = HtmlReport::new(theme.clone());
    match report.generate_from_result(domain, run_result, output_path) {
        Ok(_) => {
            if !is_json && !is_quiet {
                println!(
                    "  {} Report saved to: {}",
                    style("✓").green(),
                    output_path.display()
                );
            }
        }
        Err(e) => {
            if !is_json && !is_quiet {
                println!("  {} Failed to generate report: {}", style("✗").red(), e);
            }
        }
    }
    Ok(())
}

/// Re-exec the current process for a fresh interactive session
fn exec_process(exe: &Path) -> std::io::Error {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // This replaces the current process entirely
        std::process::Command::new(exe).exec()
    }
    #[cfg(not(unix))]
    {
        match std::process::Command::new(exe).status() {
            Ok(status) => std::process::exit(status.code().unwrap_or(0)),
            Err(e) => e,
        }
    }
}

fn generate_default_filename(domain: &str) -> String {
    let domain_safe = domain.replace('.', "-");
    let timestamp = Local::now().format("%Y-%m-%d-%H%M");
    format!("report-{}-{}.html", domain_safe, timestamp)
}
