//! Diff command implementation - compare two certificates

use crate::certificate::get_certificate_chain;
use crate::cli::OutputFormat;
use crate::error::{Result, SslToolkitError};
use crate::output::{create_spinner, print_header, print_json};
use console::style;
use serde::Serialize;
use std::time::Duration;

#[derive(Serialize)]
pub struct DiffResult {
    pub first: CertSummary,
    pub second: CertSummary,
    pub differences: Vec<Difference>,
    pub same: Vec<String>,
}

#[derive(Serialize)]
pub struct CertSummary {
    pub source: String,
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub days_until_expiry: i64,
    pub serial_number: String,
    pub fingerprint_sha256: String,
    pub key_algorithm: String,
    pub signature_algorithm: String,
}

#[derive(Serialize)]
pub struct Difference {
    pub field: String,
    pub first_value: String,
    pub second_value: String,
}

/// Run the diff command
pub async fn run_diff(
    first: &str,
    second: Option<&str>,
    ip_override: Option<&str>,
    port: u16,
    format: OutputFormat,
) -> Result<()> {
    let timeout = Duration::from_secs(10);

    // Get first certificate
    let spinner = create_spinner(&format!("Retrieving certificate from {}...", first));
    let (chain1, _, _, _) = get_certificate_chain(first, port, None, timeout)?;
    spinner.finish_and_clear();

    let cert1 = chain1
        .leaf()
        .ok_or_else(|| SslToolkitError::Certificate("No certificate found for first source".to_string()))?;

    // Get second certificate
    let (chain2, second_source) = if let Some(second_domain) = second {
        let spinner = create_spinner(&format!("Retrieving certificate from {}...", second_domain));
        let (chain, _, _, _) = get_certificate_chain(second_domain, port, None, timeout)?;
        spinner.finish_and_clear();
        (chain, second_domain.to_string())
    } else if let Some(ip) = ip_override {
        let spinner = create_spinner(&format!("Retrieving certificate from {} (IP: {})...", first, ip));
        let (chain, _, _, _) = get_certificate_chain(first, port, Some(ip), timeout)?;
        spinner.finish_and_clear();
        (chain, format!("{} (IP: {})", first, ip))
    } else {
        return Err(SslToolkitError::Config(
            "Must specify either a second domain or --ip flag".to_string(),
        ));
    };

    let cert2 = chain2
        .leaf()
        .ok_or_else(|| SslToolkitError::Certificate("No certificate found for second source".to_string()))?;

    // Create summaries
    let summary1 = CertSummary {
        source: first.to_string(),
        subject: cert1.subject.common_name.clone().unwrap_or_default(),
        issuer: cert1.issuer.common_name.clone().unwrap_or_default(),
        not_before: cert1.not_before.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        not_after: cert1.not_after.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        days_until_expiry: cert1.days_until_expiry,
        serial_number: cert1.serial_number.clone(),
        fingerprint_sha256: cert1.fingerprint_sha256.clone(),
        key_algorithm: cert1.key_algorithm.to_string(),
        signature_algorithm: cert1.signature_algorithm.clone(),
    };

    let summary2 = CertSummary {
        source: second_source.clone(),
        subject: cert2.subject.common_name.clone().unwrap_or_default(),
        issuer: cert2.issuer.common_name.clone().unwrap_or_default(),
        not_before: cert2.not_before.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        not_after: cert2.not_after.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        days_until_expiry: cert2.days_until_expiry,
        serial_number: cert2.serial_number.clone(),
        fingerprint_sha256: cert2.fingerprint_sha256.clone(),
        key_algorithm: cert2.key_algorithm.to_string(),
        signature_algorithm: cert2.signature_algorithm.clone(),
    };

    // Find differences
    let mut differences = Vec::new();
    let mut same = Vec::new();

    macro_rules! compare_field {
        ($field:expr, $val1:expr, $val2:expr) => {
            if $val1 != $val2 {
                differences.push(Difference {
                    field: $field.to_string(),
                    first_value: $val1.to_string(),
                    second_value: $val2.to_string(),
                });
            } else {
                same.push($field.to_string());
            }
        };
    }

    compare_field!("Subject", &summary1.subject, &summary2.subject);
    compare_field!("Issuer", &summary1.issuer, &summary2.issuer);
    compare_field!("Valid From", &summary1.not_before, &summary2.not_before);
    compare_field!("Valid Until", &summary1.not_after, &summary2.not_after);
    compare_field!("Serial Number", &summary1.serial_number, &summary2.serial_number);
    compare_field!("Fingerprint", &summary1.fingerprint_sha256, &summary2.fingerprint_sha256);
    compare_field!("Key Algorithm", &summary1.key_algorithm, &summary2.key_algorithm);
    compare_field!("Signature Algorithm", &summary1.signature_algorithm, &summary2.signature_algorithm);

    let result = DiffResult {
        first: summary1,
        second: summary2,
        differences,
        same,
    };

    // Output
    match format {
        OutputFormat::Json => {
            print_json(&result)?;
        }
        _ => {
            print_header("Certificate Comparison");

            println!(
                "  {} {} vs {}",
                style("Comparing:").bold(),
                style(first).cyan(),
                style(&second_source).cyan()
            );
            println!();

            if result.differences.is_empty() {
                println!(
                    "  {} Certificates are {}",
                    style("✓").green(),
                    style("IDENTICAL").green().bold()
                );
            } else {
                println!(
                    "  {} Found {} differences:",
                    style("!").yellow(),
                    style(result.differences.len()).yellow().bold()
                );
                println!();

                for diff in &result.differences {
                    println!("  {} {}", style("─").dim(), style(&diff.field).bold());
                    println!(
                        "    {} {}",
                        style("First:").dim(),
                        if diff.first_value.len() > 50 {
                            format!("{}...", &diff.first_value[..50])
                        } else {
                            diff.first_value.clone()
                        }
                    );
                    println!(
                        "    {} {}",
                        style("Second:").dim(),
                        if diff.second_value.len() > 50 {
                            format!("{}...", &diff.second_value[..50])
                        } else {
                            diff.second_value.clone()
                        }
                    );
                    println!();
                }
            }

            if !result.same.is_empty() {
                println!(
                    "  {} Same: {}",
                    style("ℹ").blue(),
                    result.same.join(", ")
                );
            }
        }
    }

    Ok(())
}
