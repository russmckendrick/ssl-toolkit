//! Certificate chain tree visualization

use crate::models::{CertificateSummary, CertificateType};
use console::style;

/// Format a tree visualization of the certificate chain to a string
pub fn format_cert_chain(chain: &[CertificateSummary]) -> String {
    let mut out = String::new();
    for (i, cert) in chain.iter().enumerate() {
        let is_last = i == chain.len() - 1;
        let connector = if i == 0 {
            "    "
        } else if is_last {
            "    └── "
        } else {
            "    ├── "
        };

        let icon = match cert.cert_type {
            CertificateType::Leaf => "📄",
            CertificateType::Intermediate => "📋",
            CertificateType::Root => "🔐",
        };

        let type_label = match cert.cert_type {
            CertificateType::Leaf => "Server",
            CertificateType::Intermediate => "Intermediate",
            CertificateType::Root => "Root",
        };

        let validity = if cert.is_valid {
            if cert.days_until_expiry <= 30 {
                style(format!("{} days", cert.days_until_expiry)).yellow()
            } else {
                style(format!("{} days", cert.days_until_expiry)).green()
            }
        } else {
            style("EXPIRED".to_string()).red().bold()
        };

        out.push_str(&format!(
            "{}{} {}: {} ({})\n",
            connector,
            icon,
            style(type_label).bold(),
            cert.subject_cn,
            validity
        ));
    }
    out
}

/// Print a tree visualization of the certificate chain
pub fn print_cert_chain(chain: &[CertificateSummary]) {
    for (i, cert) in chain.iter().enumerate() {
        let is_last = i == chain.len() - 1;
        let connector = if i == 0 {
            "    "
        } else if is_last {
            "    └── "
        } else {
            "    ├── "
        };

        let icon = match cert.cert_type {
            CertificateType::Leaf => "📄",
            CertificateType::Intermediate => "📋",
            CertificateType::Root => "🔐",
        };

        let type_label = match cert.cert_type {
            CertificateType::Leaf => "Server",
            CertificateType::Intermediate => "Intermediate",
            CertificateType::Root => "Root",
        };

        let validity = if cert.is_valid {
            if cert.days_until_expiry <= 30 {
                style(format!("{} days", cert.days_until_expiry)).yellow()
            } else {
                style(format!("{} days", cert.days_until_expiry)).green()
            }
        } else {
            style("EXPIRED".to_string()).red().bold()
        };

        println!(
            "{}{} {}: {} ({})",
            connector,
            icon,
            style(type_label).bold(),
            cert.subject_cn,
            validity
        );
    }
}
