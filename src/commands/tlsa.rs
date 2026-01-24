//! TLSA record generation command

use crate::certificate::get_certificate_chain;
use crate::cli::OutputFormat;
use crate::dns::{
    format_tlsa_for_zone, generate_tlsa_record, TlsaMatchingType, TlsaSelector, TlsaUsage,
};
use crate::error::{Result, SslToolkitError};
use crate::output::{create_spinner, print_header, print_info, print_json, print_success};
use console::style;
use serde::Serialize;
use std::time::Duration;

#[derive(Serialize)]
pub struct TlsaOutput {
    pub domain: String,
    pub port: u16,
    pub usage: u8,
    pub selector: u8,
    pub matching_type: u8,
    pub certificate_data: String,
    pub zone_record: String,
    pub usage_description: String,
    pub selector_description: String,
    pub matching_type_description: String,
}

/// Run the TLSA generation command
pub async fn run_tlsa(
    domain: &str,
    port: u16,
    usage: u8,
    selector: u8,
    matching_type: u8,
    format: OutputFormat,
) -> Result<()> {
    // Validate parameters
    let tlsa_usage = TlsaUsage::from_u8(usage)
        .ok_or_else(|| SslToolkitError::Config(format!("Invalid TLSA usage value: {} (must be 0-3)", usage)))?;

    let tlsa_selector = TlsaSelector::from_u8(selector)
        .ok_or_else(|| SslToolkitError::Config(format!("Invalid TLSA selector value: {} (must be 0-1)", selector)))?;

    let tlsa_matching = TlsaMatchingType::from_u8(matching_type)
        .ok_or_else(|| SslToolkitError::Config(format!("Invalid TLSA matching type: {} (must be 0-2)", matching_type)))?;

    let spinner = create_spinner(&format!("Retrieving certificate from {}:{}...", domain, port));

    let (chain, _, _, _) = get_certificate_chain(domain, port, None, Duration::from_secs(10))?;

    spinner.finish_and_clear();

    let cert = chain
        .leaf()
        .ok_or_else(|| SslToolkitError::Certificate("No certificate found".to_string()))?;

    let tlsa_record = generate_tlsa_record(cert, tlsa_usage, tlsa_selector, tlsa_matching)?;
    let zone_record = format_tlsa_for_zone(domain, port, &tlsa_record);

    let output = TlsaOutput {
        domain: domain.to_string(),
        port,
        usage,
        selector,
        matching_type,
        certificate_data: tlsa_record.certificate_data.clone(),
        zone_record: zone_record.clone(),
        usage_description: tlsa_usage.description().to_string(),
        selector_description: tlsa_selector.description().to_string(),
        matching_type_description: tlsa_matching.description().to_string(),
    };

    match format {
        OutputFormat::Json => {
            print_json(&output)?;
        }
        _ => {
            print_header(&format!("TLSA Record for {}:{}", domain, port));

            println!("  {} TLSA Parameters:", style("ℹ").blue());
            println!(
                "     Usage ({})      : {} - {}",
                usage,
                style(tlsa_usage.description()).cyan(),
                match usage {
                    0 => "CA constraint",
                    1 => "Service certificate constraint",
                    2 => "Trust anchor assertion (DANE-TA)",
                    3 => "Domain-issued certificate (DANE-EE)",
                    _ => "Unknown",
                }
            );
            println!(
                "     Selector ({})   : {} - {}",
                selector,
                style(tlsa_selector.description()).cyan(),
                match selector {
                    0 => "Use full certificate",
                    1 => "Use SubjectPublicKeyInfo",
                    _ => "Unknown",
                }
            );
            println!(
                "     Matching ({})   : {} - {}",
                matching_type,
                style(tlsa_matching.description()).cyan(),
                match matching_type {
                    0 => "Exact match",
                    1 => "SHA-256 hash",
                    2 => "SHA-512 hash",
                    _ => "Unknown",
                }
            );

            println!();
            println!("  {} DNS Zone Record:", style("📝").yellow());
            println!();
            println!("     {}", style(&zone_record).green().bold());
            println!();

            print_info("Add this record to your DNS zone to enable DANE/TLSA validation");

            println!();
            println!("  {} Certificate Data (for reference):", style("🔑").cyan());
            println!("     {}", truncate_hash(&tlsa_record.certificate_data));
        }
    }

    Ok(())
}

fn truncate_hash(hash: &str) -> String {
    if hash.len() > 64 {
        format!("{}...{}", &hash[..32], &hash[hash.len() - 32..])
    } else {
        hash.to_string()
    }
}
