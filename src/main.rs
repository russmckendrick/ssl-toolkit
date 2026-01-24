//! SSL Toolkit - A comprehensive SSL/TLS certificate analysis tool
//!
//! This tool provides functionality for:
//! - Checking SSL certificates for domains
//! - Analyzing certificate chains
//! - Security grading
//! - DNS analysis including DANE/TLSA
//! - Certificate Transparency log searching
//! - Batch processing and monitoring

mod certificate;
mod cli;
mod commands;
mod ct;
mod dns;
mod error;
mod hpkp;
mod output;
mod utils;

use clap::Parser;
use cli::{Cli, Commands, InteractiveSession, OutputFormat};
use console::style;
use error::Result;
use std::path::PathBuf;
use std::time::Duration;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    // Install the ring crypto provider for rustls
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_target(false)
        .init();

    if let Err(e) = run().await {
        eprintln!("{} {}", style("Error:").red().bold(), e);
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();

    // Handle color preference
    if cli.no_color {
        console::set_colors_enabled(false);
    }

    // Interactive mode
    if cli.interactive {
        let mut session = InteractiveSession::new();
        return session.run().await;
    }

    // Handle subcommands
    if let Some(command) = cli.command {
        return match command {
            Commands::Check(args) => {
                if args.download_chain {
                    commands::run_check_download_chain(
                        &args.domain,
                        args.port,
                        Duration::from_secs(args.timeout),
                    )
                    .await
                } else if args.create_reminder {
                    commands::run_check_create_reminder(
                        &args.domain,
                        args.port,
                        Duration::from_secs(args.timeout),
                        args.reminder_days,
                    )
                    .await
                } else {
                    commands::run_check(
                        &args.domain,
                        args.port,
                        args.ip.as_deref(),
                        Duration::from_secs(args.timeout),
                        args.skip_dns,
                        args.skip_ct,
                        args.skip_ocsp,
                        cli.format,
                        cli.verbose,
                    )
                    .await
                }
            }
            Commands::Batch(args) => {
                commands::run_batch(
                    &args.file,
                    args.parallel,
                    Duration::from_secs(args.timeout),
                    args.skip_dns,
                    args.skip_ct,
                    args.skip_ocsp,
                    args.issues_only,
                    cli.format,
                )
                .await
            }
            Commands::Watch(args) => {
                commands::run_watch(
                    &args.domain,
                    args.interval,
                    args.count,
                    args.alert_on_change,
                    args.alert_expiry_days,
                )
                .await
            }
            Commands::Diff(args) => {
                commands::run_diff(
                    &args.first,
                    args.second.as_deref(),
                    args.ip.as_deref(),
                    args.port,
                    cli.format,
                )
                .await
            }
            Commands::Expiring(args) => {
                run_expiring_check(args.file, args.days, args.parallel, args.sort, cli.format).await
            }
            Commands::ListRoots => {
                list_root_certificates();
                Ok(())
            }
            Commands::CtSearch(args) => {
                commands::run_ct_search(
                    &args.domain,
                    args.include_expired,
                    args.limit,
                    args.issuer.as_deref(),
                    cli.format,
                )
                .await
            }
            Commands::Tlsa(args) => {
                commands::run_tlsa(
                    &args.domain,
                    args.port,
                    args.usage,
                    args.selector,
                    args.matching_type,
                    cli.format,
                )
                .await
            }
        };
    }

    // Default: check domain if provided
    if let Some(domain) = cli.domain {
        // Handle special flags
        if cli.download_chain {
            return commands::run_check_download_chain(
                &domain,
                cli.port,
                Duration::from_secs(cli.timeout),
            )
            .await;
        }

        if cli.create_reminder {
            return commands::run_check_create_reminder(
                &domain,
                cli.port,
                Duration::from_secs(cli.timeout),
                cli.reminder_days,
            )
            .await;
        }

        // Handle view-only flags
        if cli.grade {
            return run_grade_only(&domain, cli.port, cli.format).await;
        }

        if cli.chain {
            return run_chain_only(&domain, cli.port, cli.format).await;
        }

        if cli.dns {
            return run_dns_only(&domain, cli.format).await;
        }

        // Standard check
        return commands::run_check(
            &domain,
            cli.port,
            cli.ip.as_deref(),
            Duration::from_secs(cli.timeout),
            cli.skip_dns,
            cli.skip_ct,
            cli.skip_ocsp,
            cli.format,
            cli.verbose,
        )
        .await;
    }

    // No command or domain provided - show help
    println!("{}", style("SSL Toolkit").cyan().bold());
    println!("A comprehensive SSL/TLS certificate analysis tool\n");
    println!("Usage: ssl-toolkit [OPTIONS] [DOMAIN]");
    println!("       ssl-toolkit <COMMAND>\n");
    println!("Run 'ssl-toolkit --help' for more information.");
    println!("Run 'ssl-toolkit --interactive' for interactive mode.");

    Ok(())
}

async fn run_grade_only(domain: &str, port: u16, format: OutputFormat) -> Result<()> {
    let timeout = Duration::from_secs(10);

    let spinner = output::create_spinner(&format!("Checking {}...", domain));
    let (chain, _, _, _) = certificate::get_certificate_chain(domain, port, None, timeout)?;
    spinner.finish_and_clear();

    // Quick HSTS check
    let has_hsts = hpkp::check_hsts(domain, port)
        .await
        .map(|h| h.present)
        .unwrap_or(false);

    let grade = certificate::calculate_security_grade(&chain, has_hsts, false);

    match format {
        OutputFormat::Json => {
            output::print_json(&serde_json::json!({
                "domain": domain,
                "grade": grade.display(),
                "score": grade.score
            }))?;
        }
        _ => {
            output::print_security_grade(&grade);
        }
    }

    Ok(())
}

async fn run_chain_only(domain: &str, port: u16, format: OutputFormat) -> Result<()> {
    let timeout = Duration::from_secs(10);

    let spinner = output::create_spinner(&format!("Retrieving certificate chain from {}...", domain));
    let (chain, _, _, _) = certificate::get_certificate_chain(domain, port, None, timeout)?;
    spinner.finish_and_clear();

    match format {
        OutputFormat::Json => {
            output::print_json(&chain)?;
        }
        _ => {
            output::print_certificate_chain(&chain);
        }
    }

    Ok(())
}

async fn run_dns_only(domain: &str, format: OutputFormat) -> Result<()> {
    let spinner = output::create_spinner(&format!("Resolving DNS for {}...", domain));
    let resolver = dns::DnsResolver::new().await?;
    let dns_info = resolver.get_dns_info(domain).await?;
    spinner.finish_and_clear();

    match format {
        OutputFormat::Json => {
            output::print_json(&dns_info)?;
        }
        _ => {
            output::print_dns_info(&dns_info, true);
        }
    }

    Ok(())
}

async fn run_expiring_check(
    file: Option<PathBuf>,
    days: i64,
    parallel: usize,
    sort: bool,
    format: OutputFormat,
) -> Result<()> {
    use futures::stream::{self, StreamExt};
    use std::io::{self, BufRead};

    // Read domains from file or stdin
    let domains: Vec<String> = if let Some(path) = file {
        let file = std::fs::File::open(&path)
            .map_err(|e| error::SslToolkitError::File(format!("Failed to open file: {}", e)))?;
        io::BufReader::new(file)
            .lines()
            .filter_map(|l| l.ok())
            .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
            .collect()
    } else {
        io::stdin()
            .lock()
            .lines()
            .filter_map(|l| l.ok())
            .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
            .collect()
    };

    if domains.is_empty() {
        return Err(error::SslToolkitError::Config("No domains provided".to_string()));
    }

    let pb = output::create_progress_bar(domains.len() as u64, "Checking expiry");
    let timeout = Duration::from_secs(10);

    #[derive(serde::Serialize)]
    struct ExpiryResult {
        domain: String,
        days_until_expiry: i64,
        expires: String,
        issuer: String,
    }

    let results: Vec<ExpiryResult> = stream::iter(domains)
        .map(|domain| {
            let timeout = timeout;
            async move {
                match certificate::get_certificate_chain(&domain, 443, None, timeout) {
                    Ok((chain, _, _, _)) => {
                        chain.leaf().map(|cert| ExpiryResult {
                            domain: domain.clone(),
                            days_until_expiry: cert.days_until_expiry,
                            expires: cert.not_after.format("%Y-%m-%d").to_string(),
                            issuer: cert.issuer.common_name.clone().unwrap_or_default(),
                        })
                    }
                    Err(_) => None,
                }
            }
        })
        .buffer_unordered(parallel)
        .inspect(|_| pb.inc(1))
        .filter_map(|r| async { r })
        .collect()
        .await;

    pb.finish_and_clear();

    // Filter to only expiring
    let mut expiring: Vec<ExpiryResult> = results
        .into_iter()
        .filter(|r| r.days_until_expiry <= days)
        .collect();

    if sort {
        expiring.sort_by_key(|r| r.days_until_expiry);
    }

    match format {
        OutputFormat::Json => {
            output::print_json(&expiring)?;
        }
        _ => {
            output::print_header(&format!("Certificates Expiring Within {} Days", days));

            if expiring.is_empty() {
                println!("  No certificates expiring within {} days", days);
            } else {
                for result in &expiring {
                    let status_text = if result.days_until_expiry < 0 {
                        "EXPIRED".to_string()
                    } else {
                        format!("{} days", result.days_until_expiry)
                    };

                    let status = if result.days_until_expiry < 0 {
                        style(status_text).red().bold()
                    } else if result.days_until_expiry <= 7 {
                        style(status_text).red().bold()
                    } else {
                        style(status_text).yellow().bold()
                    };

                    println!(
                        "  {} {} ({}) - Expires: {}",
                        status,
                        style(&result.domain).bold(),
                        result.issuer,
                        result.expires
                    );
                }
            }
        }
    }

    Ok(())
}

fn list_root_certificates() {
    output::print_header("Trusted Root Certificates");

    println!("  SSL Toolkit uses the Mozilla Root Certificate Program.");
    println!("  The following root certificates are trusted:\n");

    // List some well-known roots from webpki-roots
    let roots = [
        "DigiCert Global Root CA",
        "DigiCert Global Root G2",
        "DigiCert High Assurance EV Root CA",
        "ISRG Root X1 (Let's Encrypt)",
        "ISRG Root X2 (Let's Encrypt)",
        "GlobalSign Root CA",
        "GlobalSign Root CA - R3",
        "Comodo RSA Certification Authority",
        "Sectigo (formerly Comodo CA)",
        "GeoTrust Global CA",
        "Amazon Root CA 1-4",
        "Baltimore CyberTrust Root",
        "Entrust Root Certification Authority",
        "GoDaddy Root Certificate Authority",
        "Microsoft Root Certificate Authority",
        "QuoVadis Root CA",
        "Starfield Root Certificate Authority",
        "SwissSign Gold CA",
        "T-TeleSec GlobalRoot Class 2/3",
        "Thawte Primary Root CA",
        "VeriSign Class 3 Public Primary Certification Authority",
    ];

    for root in roots {
        println!("  {} {}", style("•").cyan(), root);
    }

    println!("\n  Total: {} root CAs in the trust store", roots.len());
    println!("\n  For the complete list, see: https://wiki.mozilla.org/CA");
}
