//! HTML report generation for SSL toolkit
//!
//! Generates professional-looking HTML reports with embedded assets.

use crate::certificate::{CertificateInfo, SecurityGrade, CertificateChain};
use crate::error::{Result, SslToolkitError};
use crate::tui::widgets::results::ResultsData;
use crate::dns::DnsInfo;
use chrono::Utc;
use std::path::Path;
use base64::{Engine as _, engine::general_purpose};

// Embed SVG logo
const LOGO_SVG: &[u8] = include_bytes!("../../assets/logo.svg");

// Brand colors
const COLOR_PRIMARY: &str = "#053E51";      // Dark blue
const COLOR_ACCENT: &str = "#EB831E";       // Orange
const COLOR_BG: &str = "#F8F9FA";           // Light gray background
const COLOR_CARD_BG: &str = "#FFFFFF";      // White card background
const COLOR_TEXT: &str = "#333333";         // Dark gray text
const COLOR_TEXT_MUTED: &str = "#666666";   // Muted text
const COLOR_BORDER: &str = "#E0E0E0";       // Light border

pub fn export_html(data: &ResultsData, path: &Path) -> Result<()> {
    let html_content = generate_html(data);
    std::fs::write(path, html_content).map_err(|e| SslToolkitError::Export(e.to_string()))?;
    Ok(())
}

fn generate_html(data: &ResultsData) -> String {
    let logo_base64 = general_purpose::STANDARD.encode(LOGO_SVG);
    let generated_date = Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSL Security Report - {domain}</title>
    <style>
        :root {{
            --primary: {primary};
            --accent: {accent};
            --bg: {bg};
            --card-bg: {card_bg};
            --text: {text};
            --text-muted: {text_muted};
            --border: {border};
            --success: #228B22;
            --warning: #B8860B;
            --danger: #B22222;
        }}
        
        * {{
            box-sizing: border_box;
            margin: 0;
            padding: 0;
        }}
        
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            line-height: 1.6;
            -webkit-font-smoothing: antialiased;
        }}
        
        .container {{
            max-width: 1000px;
            margin: 0 auto;
            padding: 40px 20px;
        }}
        
        /* Header */
        .header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 40px;
            padding-bottom: 20px;
            border-bottom: 2px solid var(--accent);
        }}
        
        .brand {{
            display: flex;
            align-items: center;
            gap: 20px;
        }}
        
        .logo {{
            height: 60px;
            width: auto;
        }}
        
        .report-title h1 {{
            color: var(--primary);
            font-size: 24px;
            font-weight: 700;
        }}
        
        .meta {{
            text-align: right;
            font-size: 14px;
            color: var(--text-muted);
        }}
        
        /* Cards */
        .card {{
            background: var(--card-bg);
            border-radius: 12px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            margin-bottom: 30px;
            overflow: hidden;
            border: 1px solid var(--border);
        }}
        
        .card-header {{
            background: rgba(5, 62, 81, 0.03);
            padding: 20px 30px;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .card-title {{
            color: var(--primary);
            font-size: 18px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .card-body {{
            padding: 30px;
        }}
        
        /* Grade Section */
        .grade-container {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 40px;
        }}
        
        .grade-badge {{
            width: 120px;
            height: 120px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 64px;
            font-weight: 800;
            color: white;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
        }}
        
        .grade-info {{
            flex: 1;
        }}
        
        .score-bar {{
            height: 10px;
            background: #eee;
            border-radius: 5px;
            margin: 10px 0 20px;
            overflow: hidden;
        }}
        
        .score-fill {{
            height: 100%;
            border-radius: 5px;
            transition: width 0.5s ease;
        }}
        
        /* Tables */
        .data-table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        .data-table th, .data-table td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        
        .data-table th {{
            color: var(--primary);
            font-weight: 600;
            width: 35%;
        }}
        
        .data-table tr:last-child td {{
            border-bottom: none;
        }}
        
        .status-badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
        }}
        
        .status-ok {{ background: rgba(34, 139, 34, 0.1); color: var(--success); }}
        .status-warn {{ background: rgba(184, 134, 11, 0.1); color: var(--warning); }}
        .status-fail {{ background: rgba(178, 34, 34, 0.1); color: var(--danger); }}
        
        .chain-node {{
            display: flex;
            align-items: center;
            margin-bottom: 12px;
            font-family: monospace;
            font-size: 14px;
        }}

        .chain-visual {{
            margin-right: 15px;
            color: var(--accent);
        }}
        
        .footer {{
            text-align: center;
            margin-top: 60px;
            color: var(--text-muted);
            font-size: 13px;
        }}

        /* Icons */
        .icon {{ width: 20px; height: 20px; stroke-width: 2; stroke: currentColor; fill: none; stroke-linecap: round; stroke-linejoin: round; }}
        
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div class="brand">
                <img src="data:image/svg+xml;base64,{logo}" alt="Company Logo" class="logo">
                <div class="report-title">
                    <h1>SSL Security Report</h1>
                </div>
            </div>
            <div class="meta">
                <p><strong>Domain:</strong> {domain}:{port}</p>
                <p><strong>Generated:</strong> {date}</p>
            </div>
        </header>

        {grade_section}
        {cert_section}
        {chain_section}
        {dns_section}

        <footer class="footer">
            <p>Generated by SSL Toolkit | <a href="https://github.com/russmckendrick/ssl-toolkit" style="color: inherit;">https://github.com/russmckendrick/ssl-toolkit</a></p>
        </footer>
    </div>
</body>
</html>
"#,
        domain = data.domain,
        primary = COLOR_PRIMARY,
        accent = COLOR_ACCENT,
        bg = COLOR_BG,
        card_bg = COLOR_CARD_BG,
        text = COLOR_TEXT,
        text_muted = COLOR_TEXT_MUTED,
        border = COLOR_BORDER,
        logo = logo_base64,
        port = data.port,
        date = generated_date,
        grade_section = render_grade_section(data.grade.as_ref()),
        cert_section = render_cert_section(data.chain.as_ref()),
        chain_section = render_chain_section(data.chain.as_ref()),
        dns_section = render_dns_section(data.dns.as_ref()),
    )
}

fn render_grade_section(grade: Option<&SecurityGrade>) -> String {
    if let Some(g) = grade {
        let color = match g.grade {
            'A' => "var(--success)",
            'B' => "#008080", // Teal
            'C' => "var(--warning)",
            'D' => "var(--accent)",
            _ => "var(--danger)",
        };

        let factors_html = g.factors.iter().map(|f| {
            let (icon, color_cls) = match f.status {
                crate::certificate::security::FactorStatus::Pass => ("✓", "status-ok"),
                crate::certificate::security::FactorStatus::Warning => ("!", "status-warn"),
                crate::certificate::security::FactorStatus::Fail => ("✕", "status-fail"),
                crate::certificate::security::FactorStatus::NotApplicable => ("-", "status-muted"),
            };
            format!(
                r#"<tr>
                    <td><span class="status-badge {cls}">{icon}</span></td>
                    <td><strong>{name}</strong></td>
                    <td style="color: var(--text-muted);">{desc}</td>
                    <td style="text-align: right;">{pts}/{max}</td>
                </tr>"#,
                cls = color_cls,
                icon = icon,
                name = f.name,
                desc = f.description,
                pts = f.points,
                max = f.max_points
            )
        }).collect::<Vec<_>>().join("");

        format!(
            r#"<section class="card">
                <div class="card-header">
                    <div class="card-title">Security Grade</div>
                </div>
                <div class="card-body">
                    <div class="grade-container">
                        <div class="grade-badge" style="background: {color};">
                            {grade}{suffix}
                        </div>
                        <div class="grade-info">
                            <div style="display: flex; justify-content: space-between; align-items: flex-end;">
                                <span style="font-size: 18px; font-weight: 600;">Security Score</span>
                                <span style="font-size: 24px; font-weight: 700; color: {color};">{score}%</span>
                            </div>
                            <div class="score-bar">
                                <div class="score-fill" style="width: {score}%; background: {color};"></div>
                            </div>
                            <p style="color: var(--text-muted);">This grade is calculated based on certificate strength, protocol support, and configuration best practices.</p>
                        </div>
                    </div>
                    <div style="margin-top: 30px;">
                        <h3 style="margin-bottom: 15px; font-size: 16px; color: var(--primary);">Grade Factors</h3>
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th style="width: 50px;">Status</th>
                                    <th style="width: 200px;">Factor</th>
                                    <th>Description</th>
                                    <th style="width: 80px; text-align: right;">Points</th>
                                </tr>
                            </thead>
                            <tbody>
                                {factors}
                            </tbody>
                        </table>
                    </div>
                </div>
            </section>"#,
            grade = g.grade,
            suffix = if g.grade == 'A' && g.score >= 95 { "+" } else { "" },
            color = color,
            score = g.score,
            factors = factors_html
        )
    } else {
        String::new()
    }
}

fn render_cert_section(chain: Option<&CertificateChain>) -> String {
    if let Some(chain) = chain {
        if let Some(cert) = chain.leaf() {
            let expiry_days = cert.days_until_expiry;
            let expiry_class = if expiry_days < 0 { "status-fail" } else if expiry_days < 30 { "status-warn" } else { "status-ok" };
            let expiry_text = if expiry_days < 0 { format!("Expired {} days ago", expiry_days.abs()) } else { format!("{} days", expiry_days) };
            
            let sans = if cert.subject_alt_names.is_empty() {
                "None".to_string()
            } else {
                let count = cert.subject_alt_names.len();
                let display = cert.subject_alt_names.iter().take(10).cloned().collect::<Vec<_>>().join(", ");
                if count > 10 {
                    format!("{} (+{} more)", display, count - 10)
                } else {
                    display
                }
            };

            format!(
                r#"<section class="card">
                    <div class="card-header">
                        <div class="card-title">Certificate Details</div>
                    </div>
                    <div class="card-body">
                        <table class="data-table">
                            <tbody>
                                <tr>
                                    <th>Subject</th>
                                    <td>{subject}</td>
                                </tr>
                                <tr>
                                    <th>Issuer</th>
                                    <td>{issuer}</td>
                                </tr>
                                <tr>
                                    <th>Valid From</th>
                                    <td>{not_before}</td>
                                </tr>
                                <tr>
                                    <th>Valid Until</th>
                                    <td>{not_after}</td>
                                </tr>
                                <tr>
                                    <th>Days Until Expiry</th>
                                    <td><span class="status-badge {expiry_class}">{expiry_text}</span></td>
                                </tr>
                                <tr>
                                    <th>Serial Number</th>
                                    <td style="font-family: monospace;">{serial}</td>
                                </tr>
                                <tr>
                                    <th>Key Algorithm</th>
                                    <td>{algo}</td>
                                </tr>
                                <tr>
                                    <th>Subject Alternative Names</th>
                                    <td style="font-size: 13px; color: var(--text-muted);">{sans}</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </section>"#,
                subject = cert.subject.common_name.as_deref().unwrap_or("N/A"),
                issuer = cert.issuer.common_name.as_deref().unwrap_or("N/A"),
                not_before = cert.not_before.format("%Y-%m-%d %H:%M UTC"),
                not_after = cert.not_after.format("%Y-%m-%d %H:%M UTC"),
                expiry_class = expiry_class,
                expiry_text = expiry_text,
                serial = cert.serial_number,
                algo = cert.key_algorithm,
                sans = sans
            )
        } else {
            String::new()
        }
    } else {
        String::new()
    }
}

fn render_chain_section(chain: Option<&CertificateChain>) -> String {
    if let Some(chain) = chain {
        let nodes_html = chain.certificates.iter().enumerate().map(|(i, cert)| {
            let is_last = i == chain.certificates.len() - 1;
            let is_first = i == 0;
            
            let (role, color) = if is_first {
                ("Leaf", "var(--accent)")
            } else if is_last {
                ("Root", "var(--primary)")
            } else {
                ("Intermediate", "#666")
            };

            let prefix = if is_first {
                "┌─"
            } else if is_last {
                "└─"
            } else {
                "├─"
            };

            let indent = "&nbsp;&nbsp;".repeat(i * 2);

            format!(
                r#"<div class="chain-node">
                    <span class="chain-visual">{indent}{prefix}</span>
                    <span class="status-badge" style="background: {color}; color: white; margin-right: 10px;">{role}</span>
                    <strong>{name}</strong>
                </div>"#,
                indent = indent,
                prefix = prefix,
                color = color,
                role = role,
                name = cert.subject.common_name.as_deref().unwrap_or("Unknown")
            )
        }).collect::<Vec<_>>().join("");

        format!(
            r#"<section class="card">
                <div class="card-header">
                    <div class="card-title">Trust Chain</div>
                    <div class="status-badge {status_cls}">{status_text}</div>
                </div>
                <div class="card-body">
                    {nodes}
                </div>
            </section>"#,
            status_cls = if chain.is_complete { "status-ok" } else { "status-fail" },
            status_text = if chain.is_complete { "Chain Complete" } else { "Chain Incomplete" },
            nodes = nodes_html
        )
    } else {
        String::new()
    }
}

fn render_dns_section(dns: Option<&DnsInfo>) -> String {
    if let Some(dns) = dns {
        let ipv4 = if dns.ipv4_addresses.is_empty() { "-" } else { &dns.ipv4_addresses.join(", ") };
        let ipv6 = if dns.ipv6_addresses.is_empty() { "-" } else { &dns.ipv6_addresses.join(", ") }; // Fixed: take reference to join result if possible, or just build string. Actually join returns String so no &.
        let ipv4_str = if dns.ipv4_addresses.is_empty() { "-".to_string() } else { dns.ipv4_addresses.join(", ") };
        let ipv6_str = if dns.ipv6_addresses.is_empty() { "-".to_string() } else { dns.ipv6_addresses.join(", ") };
        
        let ns_str = if dns.nameservers.is_empty() { "-".to_string() } else { dns.nameservers.join(", ") };
        
        let dnssec_html = if dns.dnssec_enabled {
            r#"<span class="status-badge status-ok">Enabled</span>"#
        } else {
            r#"<span class="status-badge status-warn">Not Detected</span>"#
        };

        let caa_html = if dns.caa_records.is_empty() {
            r#"<span style="color: var(--text-muted);">No CAA records found</span>"#.to_string()
        } else {
            dns.caa_records.iter().map(|caa| {
                format!(r#"<div style="font-family: monospace; font-size: 13px; margin-bottom: 4px;">{} {} "{}"</div>"#, caa.flags, caa.tag, caa.value)
            }).collect::<Vec<_>>().join("")
        };

        format!(
            r#"<section class="card">
                <div class="card-header">
                    <div class="card-title">DNS Information</div>
                </div>
                <div class="card-body">
                    <table class="data-table">
                        <tbody>
                            <tr>
                                <th>IPv4 Addresses</th>
                                <td>{ipv4}</td>
                            </tr>
                            <tr>
                                <th>IPv6 Addresses</th>
                                <td>{ipv6}</td>
                            </tr>
                            <tr>
                                <th>Nameservers</th>
                                <td>{ns}</td>
                            </tr>
                            <tr>
                                <th>DNSSEC</th>
                                <td>{dnssec}</td>
                            </tr>
                            <tr>
                                <th>CAA Records</th>
                                <td>{caa}</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </section>"#,
            ipv4 = ipv4_str,
            ipv6 = ipv6_str,
            ns = ns_str,
            dnssec = dnssec_html,
            caa = caa_html
        )
    } else {
        String::new()
    }
}
