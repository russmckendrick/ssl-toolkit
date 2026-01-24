//! HTML report generation

use crate::certificate::{CertificateChain, SecurityGrade};
use crate::dns::DnsInfo;
use crate::error::Result;
use chrono::Utc;
use std::fs::File;
use std::io::Write;
use std::path::Path;

/// Generate HTML report for SSL check
pub fn generate_html_report(
    domain: &str,
    chain: &CertificateChain,
    grade: Option<&SecurityGrade>,
    dns: Option<&DnsInfo>,
) -> String {
    let mut html = String::new();

    // HTML Header
    html.push_str(&format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSL Report: {}</title>
    <style>
        :root {{
            --primary: #2563eb;
            --success: #16a34a;
            --warning: #ca8a04;
            --danger: #dc2626;
            --gray-50: #f9fafb;
            --gray-100: #f3f4f6;
            --gray-200: #e5e7eb;
            --gray-700: #374151;
            --gray-900: #111827;
        }}
        * {{ box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: var(--gray-900);
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
            background: var(--gray-50);
        }}
        h1 {{ color: var(--primary); border-bottom: 3px solid var(--primary); padding-bottom: 0.5rem; }}
        h2 {{ color: var(--gray-700); margin-top: 2rem; }}
        .card {{
            background: white;
            border-radius: 8px;
            padding: 1.5rem;
            margin: 1rem 0;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
        th, td {{ padding: 0.75rem; text-align: left; border-bottom: 1px solid var(--gray-200); }}
        th {{ background: var(--gray-100); font-weight: 600; }}
        tr:hover {{ background: var(--gray-50); }}
        .grade {{
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 80px;
            height: 80px;
            border-radius: 50%;
            font-size: 2rem;
            font-weight: bold;
            color: white;
        }}
        .grade-a {{ background: var(--success); }}
        .grade-b {{ background: #22c55e; }}
        .grade-c {{ background: var(--warning); }}
        .grade-d {{ background: #f97316; }}
        .grade-f {{ background: var(--danger); }}
        .status-pass {{ color: var(--success); }}
        .status-warning {{ color: var(--warning); }}
        .status-fail {{ color: var(--danger); }}
        .tag {{
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.875rem;
            font-weight: 500;
        }}
        .tag-green {{ background: #dcfce7; color: var(--success); }}
        .tag-yellow {{ background: #fef9c3; color: var(--warning); }}
        .tag-red {{ background: #fee2e2; color: var(--danger); }}
        code {{ background: var(--gray-100); padding: 0.125rem 0.375rem; border-radius: 3px; font-size: 0.875rem; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1rem; }}
        .chain-item {{
            padding: 0.75rem;
            margin: 0.5rem 0;
            border-left: 3px solid var(--primary);
            background: var(--gray-50);
        }}
        footer {{ margin-top: 3rem; text-align: center; color: var(--gray-700); font-size: 0.875rem; }}
    </style>
</head>
<body>
    <h1>SSL Certificate Report: {}</h1>
    <p><em>Generated: {}</em></p>
"#,
        domain,
        domain,
        Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    ));

    // Security Grade
    if let Some(g) = grade {
        let grade_class = match g.grade {
            'A' => "grade-a",
            'B' => "grade-b",
            'C' => "grade-c",
            'D' => "grade-d",
            _ => "grade-f",
        };

        html.push_str(&format!(
            r#"
    <h2>Security Grade</h2>
    <div class="card">
        <div style="display: flex; align-items: center; gap: 2rem;">
            <div class="grade {}">{}</div>
            <div>
                <p style="margin: 0; font-size: 1.25rem;">Score: <strong>{}%</strong></p>
            </div>
        </div>
        <h3>Grade Factors</h3>
        <table>
            <thead>
                <tr><th>Factor</th><th>Status</th><th>Points</th><th>Description</th></tr>
            </thead>
            <tbody>
"#,
            grade_class,
            g.display(),
            g.score
        ));

        for factor in &g.factors {
            let (status_class, status_icon) = match factor.status {
                crate::certificate::security::FactorStatus::Pass => ("status-pass", "✓"),
                crate::certificate::security::FactorStatus::Warning => ("status-warning", "!"),
                crate::certificate::security::FactorStatus::Fail => ("status-fail", "✗"),
                crate::certificate::security::FactorStatus::NotApplicable => ("", "-"),
            };
            html.push_str(&format!(
                r#"                <tr>
                    <td>{}</td>
                    <td class="{}">{}</td>
                    <td>{}/{}</td>
                    <td>{}</td>
                </tr>
"#,
                factor.name, status_class, status_icon, factor.points, factor.max_points, factor.description
            ));
        }

        html.push_str("            </tbody>\n        </table>\n    </div>\n");
    }

    // Certificate Information
    if let Some(cert) = chain.leaf() {
        let expiry_tag = if cert.days_until_expiry < 0 {
            format!(r#"<span class="tag tag-red">Expired {} days ago</span>"#, cert.days_until_expiry.abs())
        } else if cert.days_until_expiry <= 7 {
            format!(r#"<span class="tag tag-red">{} days (critical)</span>"#, cert.days_until_expiry)
        } else if cert.days_until_expiry <= 30 {
            format!(r#"<span class="tag tag-yellow">{} days (warning)</span>"#, cert.days_until_expiry)
        } else {
            format!(r#"<span class="tag tag-green">{} days</span>"#, cert.days_until_expiry)
        };

        html.push_str(&format!(
            r#"
    <h2>Certificate Information</h2>
    <div class="card">
        <table>
            <tr><th>Field</th><th>Value</th></tr>
            <tr><td>Subject</td><td><strong>{}</strong></td></tr>
            <tr><td>Issuer</td><td>{}</td></tr>
            <tr><td>Valid From</td><td>{}</td></tr>
            <tr><td>Valid Until</td><td>{}</td></tr>
            <tr><td>Days Until Expiry</td><td>{}</td></tr>
            <tr><td>Serial Number</td><td><code>{}</code></td></tr>
            <tr><td>Key Algorithm</td><td>{}</td></tr>
            <tr><td>Signature Algorithm</td><td>{}</td></tr>
            <tr><td>Trust Status</td><td>{}</td></tr>
            <tr><td>SHA-256 Fingerprint</td><td><code style="word-break: break-all;">{}</code></td></tr>
        </table>
"#,
            cert.subject.common_name.as_deref().unwrap_or("N/A"),
            cert.issuer.common_name.as_deref().unwrap_or("N/A"),
            cert.not_before.format("%Y-%m-%d %H:%M:%S UTC"),
            cert.not_after.format("%Y-%m-%d %H:%M:%S UTC"),
            expiry_tag,
            cert.serial_number,
            cert.key_algorithm,
            cert.signature_algorithm,
            cert.trust_status,
            format_fingerprint(&cert.fingerprint_sha256)
        ));

        // Subject Alternative Names
        if !cert.subject_alt_names.is_empty() {
            html.push_str("        <h3>Subject Alternative Names</h3>\n        <ul>\n");
            for san in &cert.subject_alt_names {
                html.push_str(&format!("            <li><code>{}</code></li>\n", san));
            }
            html.push_str("        </ul>\n");
        }

        html.push_str("    </div>\n");
    }

    // Certificate Chain
    html.push_str(&format!(
        r#"
    <h2>Certificate Chain</h2>
    <div class="card">
        <p>
            <strong>Chain Length:</strong> {} |
            <strong>Complete:</strong> {} |
            <strong>Root in Trust Store:</strong> {}
        </p>
"#,
        chain.chain_length,
        if chain.is_complete { "Yes ✓" } else { "No ✗" },
        if chain.root_in_store { "Yes ✓" } else { "Unknown" }
    ));

    for (i, cert) in chain.certificates.iter().enumerate() {
        let cert_type = if i == 0 {
            "Leaf Certificate"
        } else if i == chain.certificates.len() - 1 {
            "Root Certificate"
        } else {
            "Intermediate Certificate"
        };

        html.push_str(&format!(
            r#"        <div class="chain-item">
            <strong>{}</strong><br>
            Subject: {}<br>
            Valid Until: {}
        </div>
"#,
            cert_type,
            cert.subject.common_name.as_deref().unwrap_or("N/A"),
            cert.not_after.format("%Y-%m-%d")
        ));
    }

    html.push_str("    </div>\n");

    // DNS Information
    if let Some(dns_info) = dns {
        html.push_str(r#"
    <h2>DNS Information</h2>
    <div class="card">
        <div class="grid">
"#);

        if !dns_info.ipv4_addresses.is_empty() {
            html.push_str("            <div>\n                <h3>IPv4 Addresses</h3>\n                <ul>\n");
            for ip in &dns_info.ipv4_addresses {
                html.push_str(&format!("                    <li><code>{}</code></li>\n", ip));
            }
            html.push_str("                </ul>\n            </div>\n");
        }

        if !dns_info.ipv6_addresses.is_empty() {
            html.push_str("            <div>\n                <h3>IPv6 Addresses</h3>\n                <ul>\n");
            for ip in &dns_info.ipv6_addresses {
                html.push_str(&format!("                    <li><code>{}</code></li>\n", ip));
            }
            html.push_str("                </ul>\n            </div>\n");
        }

        if !dns_info.nameservers.is_empty() {
            html.push_str("            <div>\n                <h3>Nameservers</h3>\n                <ul>\n");
            for ns in &dns_info.nameservers {
                html.push_str(&format!("                    <li><code>{}</code></li>\n", ns));
            }
            html.push_str("                </ul>\n            </div>\n");
        }

        html.push_str("        </div>\n");

        html.push_str(&format!(
            r#"        <p>
            <strong>Nameserver Consistency:</strong> {} |
            <strong>DNSSEC:</strong> {}
        </p>
"#,
            if dns_info.is_consistent {
                r#"<span class="tag tag-green">Consistent</span>"#
            } else {
                r#"<span class="tag tag-yellow">Inconsistent</span>"#
            },
            if dns_info.dnssec_enabled {
                r#"<span class="tag tag-green">Enabled</span>"#
            } else {
                r#"<span class="tag tag-yellow">Not Detected</span>"#
            }
        ));

        html.push_str("    </div>\n");
    }

    // Footer
    html.push_str(r#"
    <footer>
        <p>Report generated by <a href="https://github.com/russmckendrick/ssl-toolkit">ssl-toolkit</a></p>
    </footer>
</body>
</html>
"#);

    html
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

/// Write HTML report to file
pub fn write_html_file(report: &str, path: &Path) -> Result<()> {
    let mut file = File::create(path)
        .map_err(|e| crate::error::SslToolkitError::File(e.to_string()))?;

    file.write_all(report.as_bytes())
        .map_err(|e| crate::error::SslToolkitError::File(e.to_string()))?;

    Ok(())
}
