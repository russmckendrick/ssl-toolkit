//! Rich terminal output formatting

use crate::certificate::{
    CertificateChain, CertificateInfo, GradeFactor, SecurityGrade, TrustStatus,
};
use crate::dns::DnsInfo;
use console::{style, Style};
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;
use tabled::{
    settings::{Style as TabledStyle, Modify, object::Rows, Alignment},
    Table, Tabled,
};

/// Create a spinner for long-running operations
pub fn create_spinner(message: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::with_template("{spinner:.cyan} {msg}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    pb.set_message(message.to_string());
    pb.enable_steady_tick(Duration::from_millis(80));
    pb
}

/// Create a progress bar for batch operations
pub fn create_progress_bar(len: u64, message: &str) -> ProgressBar {
    let pb = ProgressBar::new(len);
    pb.set_style(
        ProgressStyle::with_template(
            "{msg} [{bar:40.cyan/blue}] {pos}/{len} ({percent}%)",
        )
        .unwrap()
        .progress_chars("█▓░"),
    );
    pb.set_message(message.to_string());
    pb
}

/// Print section header
pub fn print_header(title: &str) {
    println!();
    println!(
        "{}",
        style(format!("━━━ {} ━━━", title)).cyan().bold()
    );
    println!();
}

/// Print certificate information
pub fn print_certificate_info(cert: &CertificateInfo, verbose: bool) {
    print_header("Certificate Information");

    // Basic info table
    #[derive(Tabled)]
    struct CertRow {
        #[tabled(rename = "Field")]
        field: String,
        #[tabled(rename = "Value")]
        value: String,
    }

    let mut rows = vec![
        CertRow {
            field: "Subject".to_string(),
            value: cert.subject.common_name.clone().unwrap_or_default(),
        },
        CertRow {
            field: "Issuer".to_string(),
            value: cert.issuer.common_name.clone().unwrap_or_default(),
        },
        CertRow {
            field: "Valid From".to_string(),
            value: cert.not_before.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        },
        CertRow {
            field: "Valid Until".to_string(),
            value: cert.not_after.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        },
        CertRow {
            field: "Days Until Expiry".to_string(),
            value: format_expiry_days(cert.days_until_expiry),
        },
        CertRow {
            field: "Serial Number".to_string(),
            value: cert.serial_number.clone(),
        },
        CertRow {
            field: "Key Algorithm".to_string(),
            value: cert.key_algorithm.to_string(),
        },
        CertRow {
            field: "Signature Algorithm".to_string(),
            value: cert.signature_algorithm.clone(),
        },
        CertRow {
            field: "Trust Status".to_string(),
            value: format_trust_status(&cert.trust_status),
        },
    ];

    if verbose {
        rows.push(CertRow {
            field: "Version".to_string(),
            value: format!("v{}", cert.version),
        });
        rows.push(CertRow {
            field: "Is CA".to_string(),
            value: if cert.is_ca { "Yes" } else { "No" }.to_string(),
        });
        rows.push(CertRow {
            field: "SHA256 Fingerprint".to_string(),
            value: format_fingerprint(&cert.fingerprint_sha256),
        });

        if let Some(ocsp) = &cert.ocsp_status {
            rows.push(CertRow {
                field: "OCSP Status".to_string(),
                value: ocsp.to_string(),
            });
        }

        rows.push(CertRow {
            field: "CT Logged".to_string(),
            value: if cert.ct_logged { "Yes" } else { "No" }.to_string(),
        });
    }

    let table = Table::new(rows)
        .with(TabledStyle::rounded())
        .with(Modify::new(Rows::first()).with(Alignment::center()))
        .to_string();

    println!("{}", table);

    // Subject Alternative Names
    if !cert.subject_alt_names.is_empty() {
        println!();
        println!("{}", style("Subject Alternative Names:").bold());
        for san in &cert.subject_alt_names {
            println!("  {} {}", style("•").cyan(), san);
        }
    }
}

/// Print certificate chain
pub fn print_certificate_chain(chain: &CertificateChain) {
    print_header("Certificate Chain");

    println!(
        "{} Chain length: {}",
        style("ℹ").blue(),
        chain.chain_length
    );
    println!(
        "{} Complete: {}",
        style("ℹ").blue(),
        if chain.is_complete {
            style("Yes").green()
        } else {
            style("No").red()
        }
    );
    println!(
        "{} Root in trust store: {}",
        style("ℹ").blue(),
        if chain.root_in_store {
            style("Yes").green()
        } else {
            style("Unknown").yellow()
        }
    );

    println!();

    for (i, cert) in chain.certificates.iter().enumerate() {
        let prefix = if i == 0 {
            "└─ [Leaf]"
        } else if i == chain.certificates.len() - 1 {
            "   └─ [Root]"
        } else {
            "   ├─ [Intermediate]"
        };

        let indent = "   ".repeat(i);
        let name = cert.subject.common_name.clone().unwrap_or_default();
        let status = format_trust_status(&cert.trust_status);

        println!(
            "{}{} {} {}",
            indent,
            style(prefix).cyan(),
            style(&name).bold(),
            status
        );
    }
}

/// Print security grade
pub fn print_security_grade(grade: &SecurityGrade) {
    print_header("Security Grade");

    let grade_style = match grade.grade {
        'A' => Style::new().green().bold(),
        'B' => Style::new().cyan().bold(),
        'C' => Style::new().yellow().bold(),
        'D' => Style::new().red().bold(),
        _ => Style::new().red().bold(),
    };

    let grade_display = if grade.plus {
        format!("{}+", grade.grade)
    } else {
        grade.grade.to_string()
    };

    println!(
        "  ┌───────────────────┐"
    );
    println!(
        "  │  Grade: {}        │",
        grade_style.apply_to(&grade_display)
    );
    println!(
        "  │  Score: {:>3}%     │",
        grade.score
    );
    println!(
        "  └───────────────────┘"
    );

    println!();
    println!("{}", style("Grade Factors:").bold());

    for factor in &grade.factors {
        let status_icon = match factor.status {
            crate::certificate::security::FactorStatus::Pass => style("✓").green(),
            crate::certificate::security::FactorStatus::Warning => style("!").yellow(),
            crate::certificate::security::FactorStatus::Fail => style("✗").red(),
            crate::certificate::security::FactorStatus::NotApplicable => style("-").dim(),
        };

        println!(
            "  {} {}: {} ({}/{})",
            status_icon,
            style(&factor.name).bold(),
            factor.description,
            factor.points,
            factor.max_points
        );
    }
}

/// Print DNS information
pub fn print_dns_info(dns: &DnsInfo, verbose: bool) {
    print_header("DNS Information");

    // IP Addresses
    if !dns.ipv4_addresses.is_empty() {
        println!("{}", style("IPv4 Addresses:").bold());
        for ip in &dns.ipv4_addresses {
            println!("  {} {}", style("•").cyan(), ip);
        }
    }

    if !dns.ipv6_addresses.is_empty() {
        println!();
        println!("{}", style("IPv6 Addresses:").bold());
        for ip in &dns.ipv6_addresses {
            println!("  {} {}", style("•").cyan(), ip);
        }
    }

    // Nameservers
    if !dns.nameservers.is_empty() {
        println!();
        println!("{}", style("Nameservers:").bold());
        for ns in &dns.nameservers {
            println!("  {} {}", style("•").cyan(), ns);
        }
    }

    // Consistency check
    println!();
    println!(
        "{} Nameserver consistency: {}",
        style("ℹ").blue(),
        if dns.is_consistent {
            style("Consistent").green()
        } else {
            style("Inconsistent").red()
        }
    );

    // MX Records
    if !dns.mx_records.is_empty() && verbose {
        println!();
        println!("{}", style("MX Records:").bold());
        for mx in &dns.mx_records {
            println!(
                "  {} {} (priority: {})",
                style("•").cyan(),
                mx.exchange,
                mx.preference
            );
        }
    }

    // CAA Records
    if !dns.caa_records.is_empty() {
        println!();
        println!("{}", style("CAA Records:").bold());
        for caa in &dns.caa_records {
            println!(
                "  {} {} {} \"{}\"",
                style("•").cyan(),
                caa.flags,
                caa.tag,
                caa.value
            );
        }
    }

    // Email security records
    if verbose {
        if let Some(spf) = &dns.spf_record {
            println!();
            println!("{} {}", style("SPF:").bold(), spf);
        }

        if let Some(dmarc) = &dns.dmarc_record {
            println!();
            println!("{} {}", style("DMARC:").bold(), dmarc);
        }
    }

    // DNSSEC
    println!();
    println!(
        "{} DNSSEC: {}",
        style("ℹ").blue(),
        if dns.dnssec_enabled {
            style("Enabled").green()
        } else {
            style("Not detected").yellow()
        }
    );
}

/// Print a success message
pub fn print_success(message: &str) {
    println!("{} {}", style("✓").green().bold(), message);
}

/// Print an error message
pub fn print_error(message: &str) {
    eprintln!("{} {}", style("✗").red().bold(), message);
}

/// Print a warning message
pub fn print_warning(message: &str) {
    println!("{} {}", style("!").yellow().bold(), message);
}

/// Print an info message
pub fn print_info(message: &str) {
    println!("{} {}", style("ℹ").blue(), message);
}

fn format_expiry_days(days: i64) -> String {
    if days < 0 {
        style(format!("Expired {} days ago", days.abs()))
            .red()
            .to_string()
    } else if days == 0 {
        style("Expires today!").red().bold().to_string()
    } else if days <= 7 {
        style(format!("{} days (critical)", days))
            .red()
            .bold()
            .to_string()
    } else if days <= 30 {
        style(format!("{} days (warning)", days))
            .yellow()
            .to_string()
    } else {
        style(format!("{} days", days)).green().to_string()
    }
}

fn format_trust_status(status: &TrustStatus) -> String {
    match status {
        TrustStatus::Trusted => style("✓ Trusted").green().to_string(),
        TrustStatus::Untrusted => style("✗ Untrusted").red().to_string(),
        TrustStatus::SelfSigned => style("! Self-Signed").yellow().to_string(),
        TrustStatus::Expired => style("✗ Expired").red().to_string(),
        TrustStatus::NotYetValid => style("✗ Not Yet Valid").red().to_string(),
        TrustStatus::Revoked => style("✗ Revoked").red().bold().to_string(),
        TrustStatus::Unknown => style("? Unknown").dim().to_string(),
    }
}

fn format_fingerprint(fingerprint: &str) -> String {
    // Format fingerprint with colons every 2 characters
    fingerprint
        .chars()
        .collect::<Vec<_>>()
        .chunks(2)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(":")
        .to_uppercase()
}

/// Print batch check summary
pub fn print_batch_summary(
    total: usize,
    successful: usize,
    failed: usize,
    expiring_soon: usize,
    expired: usize,
) {
    print_header("Batch Check Summary");

    println!("  Total domains checked: {}", style(total).bold());
    println!("  Successful: {}", style(successful).green());
    println!("  Failed: {}", style(failed).red());
    println!("  Expiring soon (≤30 days): {}", style(expiring_soon).yellow());
    println!("  Already expired: {}", style(expired).red());
}
