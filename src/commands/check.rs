//! Check command implementation

use crate::certificate::{
    calculate_security_grade, check_ocsp_status, export_chain_as_pem, generate_ical_filename,
    generate_ical_reminder, get_certificate_chain, save_ical_file, CertificateChain,
};
use crate::cli::OutputFormat;
use crate::dns::DnsResolver;
use crate::error::Result;
use crate::hpkp::check_hsts;
use crate::output::{
    generate_html_report, generate_markdown_report, print_certificate_chain,
    print_certificate_info, print_dns_info, print_error, print_json, print_security_grade,
    print_success, to_json_output, write_html_file, write_markdown_file,
};
use std::path::Path;
use std::time::Duration;

/// Run the check command
pub async fn run_check(
    domain: &str,
    port: u16,
    ip_override: Option<&str>,
    timeout: Duration,
    skip_dns: bool,
    skip_ct: bool,
    skip_ocsp: bool,
    format: OutputFormat,
    verbose: bool,
) -> Result<()> {
    // Create spinner for certificate retrieval
    let spinner = crate::output::terminal::create_spinner(&format!(
        "Retrieving certificate from {}:{}...",
        domain, port
    ));

    // Get certificate chain
    let (mut chain, protocol, cipher, response_time) =
        get_certificate_chain(domain, port, ip_override, timeout)?;

    spinner.finish_and_clear();

    // Check OCSP if not skipped
    if !skip_ocsp {
        let spinner = crate::output::terminal::create_spinner("Checking OCSP status...");

        // Get cloned references to avoid borrow issues
        let leaf_clone = chain.certificates.first().cloned();
        let issuer_clone = chain.certificates.get(1).cloned();

        if let Some(leaf) = leaf_clone {
            if let Ok(status) = check_ocsp_status(&leaf, issuer_clone.as_ref()).await {
                if let Some(cert) = chain.certificates.first_mut() {
                    cert.ocsp_status = Some(status);
                }
            }
        }

        spinner.finish_and_clear();
    }

    // Get DNS information if not skipped
    let dns_info = if !skip_dns {
        let spinner = crate::output::terminal::create_spinner("Resolving DNS information...");
        let resolver = DnsResolver::new().await?;
        let dns = resolver.get_dns_info(domain).await.ok();
        spinner.finish_and_clear();
        dns
    } else {
        None
    };

    // Check HSTS
    let hsts_info = check_hsts(domain, port).await.ok();
    let has_hsts = hsts_info.map(|h| h.present).unwrap_or(false);

    // Check for CAA records
    let has_caa = dns_info
        .as_ref()
        .map(|d| !d.caa_records.is_empty())
        .unwrap_or(false);

    // Calculate security grade
    let grade = calculate_security_grade(&chain, has_hsts, has_caa);

    // Output based on format
    match format {
        OutputFormat::Json => {
            let output = to_json_output(domain, &chain, Some(&grade), dns_info.as_ref(), &[]);
            print_json(&output)?;
        }
        OutputFormat::Markdown => {
            let report = generate_markdown_report(domain, &chain, Some(&grade), dns_info.as_ref());
            println!("{}", report);
        }
        OutputFormat::Html => {
            let report = generate_html_report(domain, &chain, Some(&grade), dns_info.as_ref());
            let filename = format!("{}_ssl_report.html", domain.replace('.', "_"));
            write_html_file(&report, Path::new(&filename))?;
            print_success(&format!("HTML report saved to {}", filename));
        }
        OutputFormat::Table | OutputFormat::Plain => {
            // Print connection info
            println!();
            crate::output::terminal::print_info(&format!(
                "Connected to {}:{} in {}ms",
                domain, port, response_time
            ));
            crate::output::terminal::print_info(&format!("Protocol: {}", protocol));
            if let Some(c) = cipher {
                crate::output::terminal::print_info(&format!("Cipher: {}", c));
            }

            // Print security grade
            print_security_grade(&grade);

            // Print certificate info
            if let Some(cert) = chain.leaf() {
                print_certificate_info(cert, verbose);
            }

            // Print chain
            print_certificate_chain(&chain);

            // Print DNS info if available
            if let Some(dns) = &dns_info {
                print_dns_info(dns, verbose);
            }
        }
    }

    Ok(())
}

/// Run check and download chain as PEM
pub async fn run_check_download_chain(
    domain: &str,
    port: u16,
    timeout: Duration,
) -> Result<()> {
    let spinner = crate::output::terminal::create_spinner(&format!(
        "Retrieving certificate chain from {}:{}...",
        domain, port
    ));

    let (chain, _, _, _) = get_certificate_chain(domain, port, None, timeout)?;

    spinner.finish_and_clear();

    let pem = export_chain_as_pem(&chain);
    let filename = format!("{}_chain.pem", domain.replace('.', "_"));

    std::fs::write(&filename, &pem)?;
    print_success(&format!("Certificate chain saved to {}", filename));

    Ok(())
}

/// Run check and create calendar reminder
pub async fn run_check_create_reminder(
    domain: &str,
    port: u16,
    timeout: Duration,
    days_before: i64,
) -> Result<()> {
    let spinner = crate::output::terminal::create_spinner(&format!(
        "Retrieving certificate from {}:{}...",
        domain, port
    ));

    let (chain, _, _, _) = get_certificate_chain(domain, port, None, timeout)?;

    spinner.finish_and_clear();

    if let Some(cert) = chain.leaf() {
        let ical = generate_ical_reminder(cert, domain, days_before);
        let filename = generate_ical_filename(domain);

        save_ical_file(&ical, Path::new(&filename))?;
        print_success(&format!(
            "Calendar reminder saved to {} (reminder set {} days before expiry)",
            filename, days_before
        ));
    } else {
        print_error("No certificate found to create reminder for");
    }

    Ok(())
}
