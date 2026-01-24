//! PDF report generation for SSL toolkit
//!
//! Generates professional-looking PDF reports with embedded fonts and logo.

use crate::certificate::{CertificateInfo, SecurityGrade};
use crate::error::{Result, SslToolkitError};
use crate::tui::widgets::results::ResultsData;
use chrono::Utc;
use genpdf::{
    elements::{Break, Paragraph, TableLayout, Text},
    fonts, style, Document, Element, Margins, SimplePageDecorator,
};
use std::path::Path;

// Embed Liberation Sans fonts directly in the binary
const LIBERATION_SANS_REGULAR: &[u8] = include_bytes!("../../assets/liberation-fonts-ttf/LiberationSans-Regular.ttf");
const LIBERATION_SANS_BOLD: &[u8] = include_bytes!("../../assets/liberation-fonts-ttf/LiberationSans-Bold.ttf");
const LIBERATION_SANS_ITALIC: &[u8] = include_bytes!("../../assets/liberation-fonts-ttf/LiberationSans-Italic.ttf");
const LIBERATION_SANS_BOLD_ITALIC: &[u8] = include_bytes!("../../assets/liberation-fonts-ttf/LiberationSans-BoldItalic.ttf");

// Brand colors
const COLOR_PRIMARY: style::Color = style::Color::Rgb(5, 62, 81);      // Dark blue from logo
const COLOR_ACCENT: style::Color = style::Color::Rgb(235, 131, 30);    // Orange from logo
const COLOR_LIGHT_GRAY: style::Color = style::Color::Rgb(128, 128, 128);
const COLOR_DARK_GRAY: style::Color = style::Color::Rgb(64, 64, 64);

/// Export results to PDF
pub fn export_pdf(data: &ResultsData, path: &Path) -> Result<()> {
    let font_family = load_embedded_font()?;

    let mut doc = Document::new(font_family);
    doc.set_title(format!("SSL Certificate Report - {}", data.domain));
    doc.set_minimal_conformance();
    doc.set_line_spacing(1.3);

    // Set page margins
    let mut decorator = SimplePageDecorator::new();
    decorator.set_margins(Margins::trbl(25, 20, 25, 20));
    doc.set_page_decorator(decorator);

    // === HEADER SECTION ===
    render_header(&mut doc, &data.domain, data.port);

    // === SECURITY GRADE SECTION ===
    if let Some(ref grade) = data.grade {
        render_grade_section(&mut doc, grade);
    }

    // === CERTIFICATE DETAILS SECTION ===
    if let Some(ref chain) = data.chain {
        if let Some(cert) = chain.leaf() {
            render_certificate_section(&mut doc, cert);
        }

        // === CERTIFICATE CHAIN SECTION ===
        render_chain_section(&mut doc, chain);
    }

    // === DNS SECTION ===
    if let Some(ref dns) = data.dns {
        render_dns_section(&mut doc, dns);
    }

    // === FOOTER ===
    render_footer(&mut doc);

    // Save document
    doc.render_to_file(path)
        .map_err(|e| SslToolkitError::PdfGeneration(e.to_string()))?;

    Ok(())
}

/// Load embedded Liberation Sans font family
fn load_embedded_font() -> Result<genpdf::fonts::FontFamily<genpdf::fonts::FontData>> {
    let regular = fonts::FontData::new(LIBERATION_SANS_REGULAR.to_vec(), None)
        .map_err(|e| SslToolkitError::PdfGeneration(format!("Failed to load font: {}", e)))?;
    let bold = fonts::FontData::new(LIBERATION_SANS_BOLD.to_vec(), None)
        .map_err(|e| SslToolkitError::PdfGeneration(format!("Failed to load font: {}", e)))?;
    let italic = fonts::FontData::new(LIBERATION_SANS_ITALIC.to_vec(), None)
        .map_err(|e| SslToolkitError::PdfGeneration(format!("Failed to load font: {}", e)))?;
    let bold_italic = fonts::FontData::new(LIBERATION_SANS_BOLD_ITALIC.to_vec(), None)
        .map_err(|e| SslToolkitError::PdfGeneration(format!("Failed to load font: {}", e)))?;

    Ok(genpdf::fonts::FontFamily { regular, bold, italic, bold_italic })
}

/// Render the document header
fn render_header(doc: &mut Document, domain: &str, port: u16) {
    // Main title with brand color
    doc.push(
        Paragraph::new("SSL TOOLKIT")
            .styled(style::Style::new().bold().with_font_size(28).with_color(COLOR_PRIMARY))
    );

    doc.push(
        Paragraph::new("Certificate Security Report")
            .styled(style::Style::new().with_font_size(14).with_color(COLOR_ACCENT))
    );

    doc.push(Break::new(0.8));

    // Horizontal line effect using underscores
    doc.push(
        Paragraph::new("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            .styled(style::Style::new().with_color(COLOR_ACCENT))
    );

    doc.push(Break::new(0.5));

    // Domain info box
    doc.push(
        Paragraph::new(format!("Domain: {}:{}", domain, port))
            .styled(style::Style::new().bold().with_font_size(16).with_color(COLOR_PRIMARY))
    );

    doc.push(
        Paragraph::new(format!("Report Generated: {}", Utc::now().format("%Y-%m-%d %H:%M:%S UTC")))
            .styled(style::Style::new().with_font_size(10).with_color(COLOR_LIGHT_GRAY))
    );

    doc.push(Break::new(1.5));
}

/// Render the security grade section
fn render_grade_section(doc: &mut Document, grade: &SecurityGrade) {
    // Section header
    render_section_header(doc, "SECURITY GRADE");

    // Grade display with color based on grade
    let grade_color = match grade.grade {
        'A' => style::Color::Rgb(34, 197, 94),   // Green
        'B' => style::Color::Rgb(6, 182, 212),   // Cyan
        'C' => style::Color::Rgb(234, 179, 8),   // Yellow
        'D' => style::Color::Rgb(249, 115, 22),  // Orange
        _ => style::Color::Rgb(239, 68, 68),     // Red
    };

    // Large grade display
    doc.push(
        Paragraph::new(format!("  Grade: {}", grade.display()))
            .styled(style::Style::new().bold().with_font_size(24).with_color(grade_color))
    );

    doc.push(
        Paragraph::new(format!("  Score: {}%", grade.score))
            .styled(style::Style::new().with_font_size(14).with_color(COLOR_DARK_GRAY))
    );

    doc.push(Break::new(0.8));

    // Grade factors table with better styling
    let mut table = TableLayout::new(vec![1, 3, 4, 1, 1]);
    table.set_cell_decorator(genpdf::elements::FrameCellDecorator::new(true, true, false));

    // Header row
    table.row()
        .element(Text::new("").styled(style::Style::new().bold().with_font_size(9)))
        .element(Text::new("Factor").styled(style::Style::new().bold().with_font_size(9).with_color(COLOR_PRIMARY)))
        .element(Text::new("Description").styled(style::Style::new().bold().with_font_size(9).with_color(COLOR_PRIMARY)))
        .element(Text::new("Pts").styled(style::Style::new().bold().with_font_size(9).with_color(COLOR_PRIMARY)))
        .element(Text::new("Max").styled(style::Style::new().bold().with_font_size(9).with_color(COLOR_PRIMARY)))
        .push()
        .ok();

    for factor in &grade.factors {
        let (icon, icon_color) = match factor.status {
            crate::certificate::security::FactorStatus::Pass => ("✓", style::Color::Rgb(34, 197, 94)),
            crate::certificate::security::FactorStatus::Warning => ("!", style::Color::Rgb(234, 179, 8)),
            crate::certificate::security::FactorStatus::Fail => ("✗", style::Color::Rgb(239, 68, 68)),
            crate::certificate::security::FactorStatus::NotApplicable => ("-", COLOR_LIGHT_GRAY),
        };

        table.row()
            .element(Text::new(icon).styled(style::Style::new().bold().with_font_size(9).with_color(icon_color)))
            .element(Text::new(&factor.name).styled(style::Style::new().with_font_size(9)))
            .element(Text::new(&factor.description).styled(style::Style::new().with_font_size(8).with_color(COLOR_DARK_GRAY)))
            .element(Text::new(format!("{}", factor.points)).styled(style::Style::new().with_font_size(9)))
            .element(Text::new(format!("{}", factor.max_points)).styled(style::Style::new().with_font_size(9).with_color(COLOR_LIGHT_GRAY)))
            .push()
            .ok();
    }

    doc.push(table);
    doc.push(Break::new(1.5));
}

/// Render the certificate details section
fn render_certificate_section(doc: &mut Document, cert: &CertificateInfo) {
    render_section_header(doc, "CERTIFICATE DETAILS");

    // Two-column layout for certificate info
    let mut table = TableLayout::new(vec![2, 5]);
    table.set_cell_decorator(genpdf::elements::FrameCellDecorator::new(true, true, false));

    let rows = vec![
        ("Subject", cert.subject.common_name.clone().unwrap_or_else(|| "N/A".to_string())),
        ("Issuer", cert.issuer.common_name.clone().unwrap_or_else(|| "N/A".to_string())),
        ("Valid From", cert.not_before.format("%Y-%m-%d %H:%M:%S UTC").to_string()),
        ("Valid Until", cert.not_after.format("%Y-%m-%d %H:%M:%S UTC").to_string()),
        ("Days Until Expiry", if cert.days_until_expiry < 0 {
            format!("EXPIRED ({} days ago)", cert.days_until_expiry.abs())
        } else {
            format!("{} days", cert.days_until_expiry)
        }),
        ("Serial Number", cert.serial_number.clone()),
        ("Key Algorithm", cert.key_algorithm.to_string()),
        ("Signature", cert.signature_algorithm.clone()),
        ("Trust Status", cert.trust_status.to_string()),
    ];

    for (label, value) in rows {
        let value_color = if label == "Days Until Expiry" && cert.days_until_expiry < 30 {
            style::Color::Rgb(239, 68, 68) // Red for expiring soon
        } else if label == "Trust Status" && value == "Trusted" {
            style::Color::Rgb(34, 197, 94) // Green for trusted
        } else {
            COLOR_DARK_GRAY
        };

        table.row()
            .element(Text::new(label).styled(style::Style::new().bold().with_font_size(9).with_color(COLOR_PRIMARY)))
            .element(Text::new(value).styled(style::Style::new().with_font_size(9).with_color(value_color)))
            .push()
            .ok();
    }

    doc.push(table);

    // Subject Alternative Names
    if !cert.subject_alt_names.is_empty() {
        doc.push(Break::new(0.5));
        doc.push(
            Paragraph::new(format!("Subject Alternative Names ({})", cert.subject_alt_names.len()))
                .styled(style::Style::new().bold().with_font_size(10).with_color(COLOR_PRIMARY))
        );

        // Display SANs in a compact format
        let sans_text = cert.subject_alt_names.iter()
            .take(20) // Limit to first 20
            .map(|s| format!("  • {}", s))
            .collect::<Vec<_>>()
            .join("\n");

        doc.push(
            Paragraph::new(sans_text)
                .styled(style::Style::new().with_font_size(8).with_color(COLOR_DARK_GRAY))
        );

        if cert.subject_alt_names.len() > 20 {
            doc.push(
                Paragraph::new(format!("  ... and {} more", cert.subject_alt_names.len() - 20))
                    .styled(style::Style::new().italic().with_font_size(8).with_color(COLOR_LIGHT_GRAY))
            );
        }
    }

    doc.push(Break::new(1.5));
}

/// Render the certificate chain section
fn render_chain_section(doc: &mut Document, chain: &crate::certificate::CertificateChain) {
    render_section_header(doc, "CERTIFICATE CHAIN");

    // Chain summary
    let complete_icon = if chain.is_complete { "✓" } else { "✗" };
    let complete_color = if chain.is_complete { style::Color::Rgb(34, 197, 94) } else { style::Color::Rgb(239, 68, 68) };

    doc.push(
        Paragraph::new(format!("  {} Chain Complete: {}  |  Length: {}  |  Root Trusted: {}",
            complete_icon,
            if chain.is_complete { "Yes" } else { "No" },
            chain.chain_length,
            if chain.root_in_store { "Yes" } else { "Unknown" }
        ))
        .styled(style::Style::new().with_font_size(10).with_color(complete_color))
    );

    doc.push(Break::new(0.5));

    // Chain visualization
    for (i, cert) in chain.certificates.iter().enumerate() {
        let (role, role_color) = if i == 0 {
            ("LEAF", COLOR_ACCENT)
        } else if i == chain.certificates.len() - 1 {
            ("ROOT", COLOR_PRIMARY)
        } else {
            ("INTERMEDIATE", COLOR_LIGHT_GRAY)
        };

        let indent = "  ".repeat(i + 1);
        let connector = if i == 0 { "┌" } else if i == chain.certificates.len() - 1 { "└" } else { "├" };

        doc.push(
            Paragraph::new(format!("{}{}─ [{}] {}",
                indent,
                connector,
                role,
                cert.subject.common_name.clone().unwrap_or_else(|| "Unknown".to_string())
            ))
            .styled(style::Style::new().with_font_size(9).with_color(role_color))
        );
    }

    doc.push(Break::new(1.5));
}

/// Render the DNS section
fn render_dns_section(doc: &mut Document, dns: &crate::dns::DnsInfo) {
    render_section_header(doc, "DNS INFORMATION");

    let mut info_parts = Vec::new();

    if !dns.ipv4_addresses.is_empty() {
        info_parts.push(format!("IPv4: {}", dns.ipv4_addresses.join(", ")));
    }

    if !dns.ipv6_addresses.is_empty() {
        let ipv6_display: Vec<_> = dns.ipv6_addresses.iter().take(3).cloned().collect();
        let suffix = if dns.ipv6_addresses.len() > 3 {
            format!(" (+{} more)", dns.ipv6_addresses.len() - 3)
        } else {
            String::new()
        };
        info_parts.push(format!("IPv6: {}{}", ipv6_display.join(", "), suffix));
    }

    if !dns.nameservers.is_empty() {
        info_parts.push(format!("Nameservers: {}", dns.nameservers.join(", ")));
    }

    info_parts.push(format!("DNSSEC: {}", if dns.dnssec_enabled { "Enabled ✓" } else { "Not Detected" }));

    for part in info_parts {
        doc.push(
            Paragraph::new(format!("  • {}", part))
                .styled(style::Style::new().with_font_size(9).with_color(COLOR_DARK_GRAY))
        );
    }

    // CAA Records
    if !dns.caa_records.is_empty() {
        doc.push(Break::new(0.3));
        doc.push(
            Paragraph::new("  CAA Records:")
                .styled(style::Style::new().bold().with_font_size(9).with_color(COLOR_PRIMARY))
        );
        for caa in &dns.caa_records {
            doc.push(
                Paragraph::new(format!("    {} {} \"{}\"", caa.flags, caa.tag, caa.value))
                    .styled(style::Style::new().with_font_size(8).with_color(COLOR_DARK_GRAY))
            );
        }
    }

    doc.push(Break::new(1.0));
}

/// Render section header with consistent styling
fn render_section_header(doc: &mut Document, title: &str) {
    doc.push(
        Paragraph::new(title)
            .styled(style::Style::new().bold().with_font_size(12).with_color(COLOR_PRIMARY))
    );
    doc.push(
        Paragraph::new("─────────────────────────────────────────────────")
            .styled(style::Style::new().with_font_size(8).with_color(COLOR_ACCENT))
    );
    doc.push(Break::new(0.3));
}

/// Render document footer
fn render_footer(doc: &mut Document) {
    doc.push(Break::new(1.0));
    doc.push(
        Paragraph::new("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            .styled(style::Style::new().with_color(COLOR_LIGHT_GRAY))
    );
    doc.push(Break::new(0.3));
    doc.push(
        Paragraph::new("Generated by SSL Toolkit • https://github.com/russmckendrick/ssl-toolkit")
            .styled(style::Style::new().italic().with_font_size(8).with_color(COLOR_LIGHT_GRAY))
    );
}
