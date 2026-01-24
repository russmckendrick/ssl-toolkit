//! Markdown report generation

use crate::certificate::{CertificateChain, SecurityGrade};
use crate::dns::DnsInfo;
use crate::error::Result;
use chrono::Utc;
use std::fs::File;
use std::io::Write;
use std::path::Path;

/// Generate markdown report for SSL check
pub fn generate_markdown_report(
    domain: &str,
    chain: &CertificateChain,
    grade: Option<&SecurityGrade>,
    dns: Option<&DnsInfo>,
) -> String {
    let mut md = String::new();

    // Header
    md.push_str(&format!("# SSL Certificate Report: {}\n\n", domain));
    md.push_str(&format!(
        "*Generated: {}*\n\n",
        Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    ));

    // Security Grade
    if let Some(g) = grade {
        md.push_str("## Security Grade\n\n");
        md.push_str(&format!(
            "| Grade | Score |\n|-------|-------|\n| **{}** | {}% |\n\n",
            g.display(),
            g.score
        ));

        md.push_str("### Grade Factors\n\n");
        md.push_str("| Factor | Status | Points | Description |\n");
        md.push_str("|--------|--------|--------|-------------|\n");
        for factor in &g.factors {
            let status_emoji = match factor.status {
                crate::certificate::security::FactorStatus::Pass => "✅",
                crate::certificate::security::FactorStatus::Warning => "⚠️",
                crate::certificate::security::FactorStatus::Fail => "❌",
                crate::certificate::security::FactorStatus::NotApplicable => "➖",
            };
            md.push_str(&format!(
                "| {} | {} | {}/{} | {} |\n",
                factor.name, status_emoji, factor.points, factor.max_points, factor.description
            ));
        }
        md.push_str("\n");
    }

    // Certificate Information
    if let Some(cert) = chain.leaf() {
        md.push_str("## Certificate Information\n\n");

        md.push_str("| Field | Value |\n");
        md.push_str("|-------|-------|\n");
        md.push_str(&format!(
            "| Subject | {} |\n",
            cert.subject.common_name.as_deref().unwrap_or("N/A")
        ));
        md.push_str(&format!(
            "| Issuer | {} |\n",
            cert.issuer.common_name.as_deref().unwrap_or("N/A")
        ));
        md.push_str(&format!(
            "| Valid From | {} |\n",
            cert.not_before.format("%Y-%m-%d %H:%M:%S UTC")
        ));
        md.push_str(&format!(
            "| Valid Until | {} |\n",
            cert.not_after.format("%Y-%m-%d %H:%M:%S UTC")
        ));

        let expiry_status = if cert.days_until_expiry < 0 {
            format!("❌ Expired {} days ago", cert.days_until_expiry.abs())
        } else if cert.days_until_expiry <= 7 {
            format!("🔴 {} days (critical)", cert.days_until_expiry)
        } else if cert.days_until_expiry <= 30 {
            format!("🟡 {} days (warning)", cert.days_until_expiry)
        } else {
            format!("🟢 {} days", cert.days_until_expiry)
        };
        md.push_str(&format!("| Days Until Expiry | {} |\n", expiry_status));

        md.push_str(&format!(
            "| Serial Number | `{}` |\n",
            cert.serial_number
        ));
        md.push_str(&format!(
            "| Key Algorithm | {} |\n",
            cert.key_algorithm
        ));
        md.push_str(&format!(
            "| Signature Algorithm | {} |\n",
            cert.signature_algorithm
        ));
        md.push_str(&format!(
            "| Trust Status | {} |\n",
            cert.trust_status
        ));
        md.push_str("\n");

        // Subject Alternative Names
        if !cert.subject_alt_names.is_empty() {
            md.push_str("### Subject Alternative Names\n\n");
            for san in &cert.subject_alt_names {
                md.push_str(&format!("- `{}`\n", san));
            }
            md.push_str("\n");
        }

        // Fingerprint
        md.push_str("### Fingerprints\n\n");
        md.push_str(&format!(
            "- **SHA-256**: `{}`\n",
            format_fingerprint(&cert.fingerprint_sha256)
        ));
        md.push_str("\n");
    }

    // Certificate Chain
    md.push_str("## Certificate Chain\n\n");
    md.push_str(&format!(
        "- **Chain Length**: {}\n",
        chain.chain_length
    ));
    md.push_str(&format!(
        "- **Complete**: {}\n",
        if chain.is_complete { "Yes ✅" } else { "No ❌" }
    ));
    md.push_str(&format!(
        "- **Root in Trust Store**: {}\n\n",
        if chain.root_in_store { "Yes ✅" } else { "Unknown ❓" }
    ));

    md.push_str("| # | Type | Subject | Valid Until |\n");
    md.push_str("|---|------|---------|-------------|\n");
    for (i, cert) in chain.certificates.iter().enumerate() {
        let cert_type = if i == 0 {
            "Leaf"
        } else if i == chain.certificates.len() - 1 {
            "Root"
        } else {
            "Intermediate"
        };
        md.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            i + 1,
            cert_type,
            cert.subject.common_name.as_deref().unwrap_or("N/A"),
            cert.not_after.format("%Y-%m-%d")
        ));
    }
    md.push_str("\n");

    // DNS Information
    if let Some(dns_info) = dns {
        md.push_str("## DNS Information\n\n");

        if !dns_info.ipv4_addresses.is_empty() {
            md.push_str("### IPv4 Addresses\n\n");
            for ip in &dns_info.ipv4_addresses {
                md.push_str(&format!("- `{}`\n", ip));
            }
            md.push_str("\n");
        }

        if !dns_info.ipv6_addresses.is_empty() {
            md.push_str("### IPv6 Addresses\n\n");
            for ip in &dns_info.ipv6_addresses {
                md.push_str(&format!("- `{}`\n", ip));
            }
            md.push_str("\n");
        }

        if !dns_info.nameservers.is_empty() {
            md.push_str("### Nameservers\n\n");
            for ns in &dns_info.nameservers {
                md.push_str(&format!("- `{}`\n", ns));
            }
            md.push_str("\n");
        }

        md.push_str(&format!(
            "**Nameserver Consistency**: {}\n\n",
            if dns_info.is_consistent {
                "Consistent ✅"
            } else {
                "Inconsistent ⚠️"
            }
        ));

        if !dns_info.caa_records.is_empty() {
            md.push_str("### CAA Records\n\n");
            for caa in &dns_info.caa_records {
                md.push_str(&format!(
                    "- `{} {} \"{}\"`\n",
                    caa.flags, caa.tag, caa.value
                ));
            }
            md.push_str("\n");
        }

        // Email Security
        md.push_str("### Email Security Records\n\n");
        md.push_str(&format!(
            "- **SPF**: {}\n",
            dns_info
                .spf_record
                .as_ref()
                .map(|s| format!("`{}`", s))
                .unwrap_or_else(|| "Not configured ❌".to_string())
        ));
        md.push_str(&format!(
            "- **DMARC**: {}\n",
            dns_info
                .dmarc_record
                .as_ref()
                .map(|s| format!("`{}`", s))
                .unwrap_or_else(|| "Not configured ❌".to_string())
        ));
        md.push_str(&format!(
            "- **DNSSEC**: {}\n",
            if dns_info.dnssec_enabled {
                "Enabled ✅"
            } else {
                "Not detected ❓"
            }
        ));
        md.push_str("\n");
    }

    // Footer
    md.push_str("---\n\n");
    md.push_str("*Report generated by [ssl-toolkit](https://github.com/russmckendrick/ssl-toolkit)*\n");

    md
}

fn format_fingerprint(fingerprint: &str) -> String {
    fingerprint
        .chars()
        .collect::<Vec<_>>()
        .chunks(2)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(":")
        .to_uppercase()
}

/// Output markdown to stdout
pub fn print_markdown(report: &str) {
    println!("{}", report);
}

/// Write markdown report to file
pub fn write_markdown_file(report: &str, path: &Path) -> Result<()> {
    let mut file = File::create(path)
        .map_err(|e| crate::error::SslToolkitError::File(e.to_string()))?;

    file.write_all(report.as_bytes())
        .map_err(|e| crate::error::SslToolkitError::File(e.to_string()))?;

    Ok(())
}
