//! Batch check command implementation

use crate::certificate::get_certificate_chain;
use crate::cli::OutputFormat;
use crate::error::{Result, SslToolkitError};
use crate::output::{create_progress_bar, print_batch_summary, print_error, print_json};
use futures::stream::{self, StreamExt};
use serde::Serialize;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::time::Duration;

#[derive(Serialize)]
pub struct BatchResult {
    pub domain: String,
    pub status: BatchStatus,
    pub days_until_expiry: Option<i64>,
    pub issuer: Option<String>,
    pub error: Option<String>,
}

#[derive(Serialize)]
pub enum BatchStatus {
    Valid,
    Expiring,
    Expired,
    Error,
}

impl std::fmt::Display for BatchStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BatchStatus::Valid => write!(f, "Valid"),
            BatchStatus::Expiring => write!(f, "Expiring"),
            BatchStatus::Expired => write!(f, "Expired"),
            BatchStatus::Error => write!(f, "Error"),
        }
    }
}

/// Run the batch check command
pub async fn run_batch(
    file: &Path,
    parallel: usize,
    timeout: Duration,
    skip_dns: bool,
    skip_ct: bool,
    skip_ocsp: bool,
    issues_only: bool,
    format: OutputFormat,
) -> Result<()> {
    // Read domains from file
    let file = File::open(file)
        .map_err(|e| SslToolkitError::File(format!("Failed to open file: {}", e)))?;
    let reader = BufReader::new(file);

    let domains: Vec<String> = reader
        .lines()
        .filter_map(|line| {
            line.ok().and_then(|l| {
                let trimmed = l.trim().to_string();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    None
                } else {
                    Some(trimmed)
                }
            })
        })
        .collect();

    if domains.is_empty() {
        return Err(SslToolkitError::File("No domains found in file".to_string()));
    }

    let total = domains.len();
    let pb = create_progress_bar(total as u64, "Checking domains");

    // Process domains in parallel
    let results: Vec<BatchResult> = stream::iter(domains)
        .map(|domain| {
            let timeout = timeout;
            async move {
                let result = check_single_domain(&domain, timeout).await;
                result
            }
        })
        .buffer_unordered(parallel)
        .inspect(|_| pb.inc(1))
        .collect()
        .await;

    pb.finish_and_clear();

    // Calculate statistics
    let successful = results.iter().filter(|r| !matches!(r.status, BatchStatus::Error)).count();
    let failed = results.iter().filter(|r| matches!(r.status, BatchStatus::Error)).count();
    let expiring_soon = results.iter().filter(|r| matches!(r.status, BatchStatus::Expiring)).count();
    let expired = results.iter().filter(|r| matches!(r.status, BatchStatus::Expired)).count();

    // Filter results if issues_only
    let display_results: Vec<&BatchResult> = if issues_only {
        results
            .iter()
            .filter(|r| !matches!(r.status, BatchStatus::Valid))
            .collect()
    } else {
        results.iter().collect()
    };

    // Output results
    match format {
        OutputFormat::Json => {
            print_json(&display_results)?;
        }
        OutputFormat::Table | OutputFormat::Plain | OutputFormat::Markdown | OutputFormat::Html => {
            println!();

            for result in &display_results {
                let status_str = match result.status {
                    BatchStatus::Valid => console::style("✓ Valid").green().to_string(),
                    BatchStatus::Expiring => console::style("! Expiring").yellow().to_string(),
                    BatchStatus::Expired => console::style("✗ Expired").red().to_string(),
                    BatchStatus::Error => console::style("✗ Error").red().dim().to_string(),
                };

                let expiry_str = result
                    .days_until_expiry
                    .map(|d| format!("({} days)", d))
                    .unwrap_or_default();

                let error_str = result
                    .error
                    .as_ref()
                    .map(|e| format!(" - {}", e))
                    .unwrap_or_default();

                println!(
                    "  {} {} {} {}",
                    status_str,
                    console::style(&result.domain).bold(),
                    console::style(&expiry_str).dim(),
                    console::style(&error_str).red().dim()
                );
            }

            println!();
            print_batch_summary(total, successful, failed, expiring_soon, expired);
        }
    }

    Ok(())
}

async fn check_single_domain(domain: &str, timeout: Duration) -> BatchResult {
    match get_certificate_chain(domain, 443, None, timeout) {
        Ok((chain, _, _, _)) => {
            if let Some(cert) = chain.leaf() {
                let status = if cert.days_until_expiry < 0 {
                    BatchStatus::Expired
                } else if cert.days_until_expiry <= 30 {
                    BatchStatus::Expiring
                } else {
                    BatchStatus::Valid
                };

                BatchResult {
                    domain: domain.to_string(),
                    status,
                    days_until_expiry: Some(cert.days_until_expiry),
                    issuer: cert.issuer.common_name.clone(),
                    error: None,
                }
            } else {
                BatchResult {
                    domain: domain.to_string(),
                    status: BatchStatus::Error,
                    days_until_expiry: None,
                    issuer: None,
                    error: Some("No certificate found".to_string()),
                }
            }
        }
        Err(e) => BatchResult {
            domain: domain.to_string(),
            status: BatchStatus::Error,
            days_until_expiry: None,
            issuer: None,
            error: Some(e.to_string()),
        },
    }
}
