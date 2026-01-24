//! PDF report generation for SSL toolkit
//!
//! Generates professional-looking PDF reports with embedded fonts and logo.

use crate::certificate::{CertificateInfo, SecurityGrade};
use crate::error::{Result, SslToolkitError};
use crate::tui::widgets::results::ResultsData;
use chrono::Utc;
use genpdf::{
    elements::{Break, Image, Paragraph, TableLayout, Text},
    fonts, style, Document, Element, Margins, SimplePageDecorator,
};
use std::path::Path;

// Embed Liberation Sans fonts directly in the binary
const LIBERATION_SANS_REGULAR: &[u8] = include_bytes!("../../assets/liberation-fonts-ttf/LiberationSans-Regular.ttf");
const LIBERATION_SANS_BOLD: &[u8] = include_bytes!("../../assets/liberation-fonts-ttf/LiberationSans-Bold.ttf");
const LIBERATION_SANS_ITALIC: &[u8] = include_bytes!("../../assets/liberation-fonts-ttf/LiberationSans-Italic.ttf");
const LIBERATION_SANS_BOLD_ITALIC: &[u8] = include_bytes!("../../assets/liberation-fonts-ttf/LiberationSans-BoldItalic.ttf");

// Embed SVG logo
const LOGO_SVG: &[u8] = include_bytes!("../../assets/logo.svg");

// Brand colors
const COLOR_PRIMARY: style::Color = style::Color::Rgb(5, 62, 81);      // Dark blue from logo
const COLOR_ACCENT: style::Color = style::Color::Rgb(235, 131, 30);    // Orange from logo
const COLOR_LIGHT_GRAY: style::Color = style::Color::Rgb(128, 128, 128);
const COLOR_DARK_GRAY: style::Color = style::Color::Rgb(64, 64, 64);
const COLOR_GREEN: style::Color = style::Color::Rgb(34, 139, 34);      // Forest green
const COLOR_RED: style::Color = style::Color::Rgb(178, 34, 34);        // Firebrick red
const COLOR_YELLOW: style::Color = style::Color::Rgb(184, 134, 11);    // Dark goldenrod

/// Export results to PDF
pub fn export_pdf(data: &ResultsData, path: &Path) -> Result<()> {
    let font_family = load_embedded_font()?;

    let mut doc = Document::new(font_family);
    doc.set_title(format!("SSL Certificate Report - {}", data.domain));
    doc.set_minimal_conformance();
    doc.set_line_spacing(1.25);

    // Set page margins
    let mut decorator = SimplePageDecorator::new();
    decorator.set_margins(Margins::trbl(20, 20, 20, 20));
    doc.set_page_decorator(decorator);

    // === HEADER SECTION WITH LOGO ===
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

/// Render SVG logo to PNG bytes (on white background for PDF compatibility)
fn render_logo() -> Option<Vec<u8>> {
    use std::io::Cursor;

    // Parse SVG
    let opt = usvg::Options::default();
    let tree = usvg::Tree::from_data(LOGO_SVG, &opt).ok()?;

    // Calculate size (scale to 80px height for PDF)
    let target_height = 80.0;
    let scale = target_height / tree.size().height();
    let width = (tree.size().width() * scale) as u32;
    let height = target_height as u32;

    // Create pixmap and fill with white background (genpdf doesn't support alpha)
    let mut pixmap = tiny_skia::Pixmap::new(width, height)?;
    pixmap.fill(tiny_skia::Color::WHITE);

    // Render SVG on top of white background
    let transform = tiny_skia::Transform::from_scale(scale, scale);
    resvg::render(&tree, transform, &mut pixmap.as_mut());

    // Convert RGBA to RGB (remove alpha channel) for genpdf compatibility
    let rgba_data = pixmap.data();
    let mut rgb_data = Vec::with_capacity((width * height * 3) as usize);
    for pixel in rgba_data.chunks(4) {
        rgb_data.push(pixel[0]); // R
        rgb_data.push(pixel[1]); // G
        rgb_data.push(pixel[2]); // B
    }

    // Encode as RGB PNG (no alpha channel)
    let mut png_data = Vec::new();
    {
        let mut encoder = png::Encoder::new(Cursor::new(&mut png_data), width, height);
        encoder.set_color(png::ColorType::Rgb);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().ok()?;
        writer.write_image_data(&rgb_data).ok()?;
    }

    Some(png_data)
}

/// Render the document header with logo
fn render_header(doc: &mut Document, domain: &str, port: u16) {
    // Try to add logo
    if let Some(png_data) = render_logo() {
        if let Ok(image) = Image::from_reader(std::io::Cursor::new(png_data)) {
            let image = image.with_alignment(genpdf::Alignment::Left);
            doc.push(image);
            doc.push(Break::new(0.5));
        }
    }

    // Main title with brand color
    doc.push(
        Paragraph::new("SSL Certificate Security Report")
            .styled(style::Style::new().bold().with_font_size(20).with_color(COLOR_PRIMARY))
    );

    doc.push(Break::new(0.3));

    // Horizontal line
    doc.push(
        Paragraph::new("________________________________________________________________________________")
            .styled(style::Style::new().with_color(COLOR_ACCENT))
    );

    doc.push(Break::new(0.5));

    // Domain info
    let mut info_table = TableLayout::new(vec![1, 3]);

    info_table.row()
        .element(Text::new("Domain:").styled(style::Style::new().bold().with_font_size(11).with_color(COLOR_PRIMARY)))
        .element(Text::new(format!("{}:{}", domain, port)).styled(style::Style::new().with_font_size(11)))
        .push()
        .ok();

    info_table.row()
        .element(Text::new("Generated:").styled(style::Style::new().bold().with_font_size(11).with_color(COLOR_PRIMARY)))
        .element(Text::new(Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string()).styled(style::Style::new().with_font_size(11).with_color(COLOR_LIGHT_GRAY)))
        .push()
        .ok();

    doc.push(info_table);
    doc.push(Break::new(1.0));
}

/// Render the security grade section
fn render_grade_section(doc: &mut Document, grade: &SecurityGrade) {
    // Section header
    render_section_header(doc, "SECURITY GRADE");

    // Grade display with color based on grade
    let grade_color = match grade.grade {
        'A' => COLOR_GREEN,
        'B' => style::Color::Rgb(0, 128, 128),  // Teal
        'C' => COLOR_YELLOW,
        'D' => COLOR_ACCENT,
        _ => COLOR_RED,
    };

    // Large grade display
    doc.push(
        Paragraph::new(format!("    Grade: {}          Score: {}%", grade.display(), grade.score))
            .styled(style::Style::new().bold().with_font_size(18).with_color(grade_color))
    );

    doc.push(Break::new(0.6));

    // Grade factors table
    doc.push(
        Paragraph::new("    Grade Factors:")
            .styled(style::Style::new().bold().with_font_size(10).with_color(COLOR_PRIMARY))
    );
    doc.push(Break::new(0.2));

    let mut table = TableLayout::new(vec![1, 2, 4, 1, 1]);
    table.set_cell_decorator(genpdf::elements::FrameCellDecorator::new(true, true, false));

    // Header row
    table.row()
        .element(Text::new("").styled(style::Style::new().bold().with_font_size(8)))
        .element(Text::new("Factor").styled(style::Style::new().bold().with_font_size(8).with_color(COLOR_PRIMARY)))
        .element(Text::new("Description").styled(style::Style::new().bold().with_font_size(8).with_color(COLOR_PRIMARY)))
        .element(Text::new("Pts").styled(style::Style::new().bold().with_font_size(8).with_color(COLOR_PRIMARY)))
        .element(Text::new("Max").styled(style::Style::new().bold().with_font_size(8).with_color(COLOR_PRIMARY)))
        .push()
        .ok();

    for factor in &grade.factors {
        let (icon, icon_color) = match factor.status {
            crate::certificate::security::FactorStatus::Pass => ("OK", COLOR_GREEN),
            crate::certificate::security::FactorStatus::Warning => ("!!", COLOR_YELLOW),
            crate::certificate::security::FactorStatus::Fail => ("XX", COLOR_RED),
            crate::certificate::security::FactorStatus::NotApplicable => ("--", COLOR_LIGHT_GRAY),
        };

        table.row()
            .element(Text::new(format!("[{}]", icon)).styled(style::Style::new().bold().with_font_size(7).with_color(icon_color)))
            .element(Text::new(&factor.name).styled(style::Style::new().with_font_size(8)))
            .element(Text::new(&factor.description).styled(style::Style::new().with_font_size(7).with_color(COLOR_DARK_GRAY)))
            .element(Text::new(format!("{}", factor.points)).styled(style::Style::new().with_font_size(8)))
            .element(Text::new(format!("{}", factor.max_points)).styled(style::Style::new().with_font_size(8).with_color(COLOR_LIGHT_GRAY)))
            .push()
            .ok();
    }

    doc.push(table);
    doc.push(Break::new(1.0));
}

/// Render the certificate details section
fn render_certificate_section(doc: &mut Document, cert: &CertificateInfo) {
    render_section_header(doc, "CERTIFICATE DETAILS");

    // Two-column layout for certificate info
    let mut table = TableLayout::new(vec![2, 5]);
    table.set_cell_decorator(genpdf::elements::FrameCellDecorator::new(true, true, false));

    let expiry_text = if cert.days_until_expiry < 0 {
        format!("EXPIRED ({} days ago)", cert.days_until_expiry.abs())
    } else {
        format!("{} days", cert.days_until_expiry)
    };

    let rows = vec![
        ("Subject", cert.subject.common_name.clone().unwrap_or_else(|| "N/A".to_string())),
        ("Issuer", cert.issuer.common_name.clone().unwrap_or_else(|| "N/A".to_string())),
        ("Valid From", cert.not_before.format("%Y-%m-%d %H:%M UTC").to_string()),
        ("Valid Until", cert.not_after.format("%Y-%m-%d %H:%M UTC").to_string()),
        ("Days Until Expiry", expiry_text),
        ("Serial Number", truncate_string(&cert.serial_number, 40)),
        ("Key Algorithm", cert.key_algorithm.to_string()),
        ("Signature", cert.signature_algorithm.clone()),
        ("Trust Status", cert.trust_status.to_string()),
    ];

    for (label, value) in rows {
        let value_color = if label == "Days Until Expiry" && cert.days_until_expiry < 30 {
            COLOR_RED
        } else if label == "Trust Status" && value == "Trusted" {
            COLOR_GREEN
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
        doc.push(Break::new(0.4));
        doc.push(
            Paragraph::new(format!("    Subject Alternative Names ({})", cert.subject_alt_names.len()))
                .styled(style::Style::new().bold().with_font_size(9).with_color(COLOR_PRIMARY))
        );

        // Display SANs in a compact format - limit display
        let display_count = cert.subject_alt_names.len().min(15);
        let sans_text = cert.subject_alt_names.iter()
            .take(display_count)
            .map(|s| format!("      - {}", s))
            .collect::<Vec<_>>()
            .join("\n");

        doc.push(
            Paragraph::new(sans_text)
                .styled(style::Style::new().with_font_size(8).with_color(COLOR_DARK_GRAY))
        );

        if cert.subject_alt_names.len() > display_count {
            doc.push(
                Paragraph::new(format!("      ... and {} more", cert.subject_alt_names.len() - display_count))
                    .styled(style::Style::new().italic().with_font_size(8).with_color(COLOR_LIGHT_GRAY))
            );
        }
    }

    doc.push(Break::new(1.0));
}

/// Render the certificate chain section
fn render_chain_section(doc: &mut Document, chain: &crate::certificate::CertificateChain) {
    render_section_header(doc, "CERTIFICATE CHAIN");

    // Chain summary with ASCII indicators
    let complete_indicator = if chain.is_complete { "[OK]" } else { "[!!]" };
    let complete_color = if chain.is_complete { COLOR_GREEN } else { COLOR_RED };
    let root_indicator = if chain.root_in_store { "[OK]" } else { "[??]" };
    let root_color = if chain.root_in_store { COLOR_GREEN } else { COLOR_YELLOW };

    let mut summary_table = TableLayout::new(vec![1, 1, 1]);

    summary_table.row()
        .element(Text::new(format!("{} Chain Complete", complete_indicator)).styled(style::Style::new().with_font_size(9).with_color(complete_color)))
        .element(Text::new(format!("Length: {}", chain.chain_length)).styled(style::Style::new().with_font_size(9).with_color(COLOR_DARK_GRAY)))
        .element(Text::new(format!("{} Root Trusted", root_indicator)).styled(style::Style::new().with_font_size(9).with_color(root_color)))
        .push()
        .ok();

    doc.push(summary_table);
    doc.push(Break::new(0.4));

    // Chain visualization using ASCII art
    doc.push(
        Paragraph::new("    Chain Hierarchy:")
            .styled(style::Style::new().bold().with_font_size(9).with_color(COLOR_PRIMARY))
    );

    for (i, cert) in chain.certificates.iter().enumerate() {
        let (role, role_color) = if i == 0 {
            ("[LEAF]", COLOR_ACCENT)
        } else if i == chain.certificates.len() - 1 {
            ("[ROOT]", COLOR_PRIMARY)
        } else {
            ("[INTM]", COLOR_LIGHT_GRAY)
        };

        let indent = "      ".to_string() + &"  ".repeat(i);
        let connector = if i == 0 { "+--" } else if i == chain.certificates.len() - 1 { "\\--" } else { "|--" };

        doc.push(
            Paragraph::new(format!("{}{} {} {}",
                indent,
                connector,
                role,
                cert.subject.common_name.clone().unwrap_or_else(|| "Unknown".to_string())
            ))
            .styled(style::Style::new().with_font_size(8).with_color(role_color))
        );
    }

    doc.push(Break::new(1.0));
}

/// Render the DNS section
fn render_dns_section(doc: &mut Document, dns: &crate::dns::DnsInfo) {
    render_section_header(doc, "DNS INFORMATION");

    let mut table = TableLayout::new(vec![2, 5]);
    table.set_cell_decorator(genpdf::elements::FrameCellDecorator::new(true, true, false));

    if !dns.ipv4_addresses.is_empty() {
        table.row()
            .element(Text::new("IPv4").styled(style::Style::new().bold().with_font_size(9).with_color(COLOR_PRIMARY)))
            .element(Text::new(dns.ipv4_addresses.join(", ")).styled(style::Style::new().with_font_size(9).with_color(COLOR_DARK_GRAY)))
            .push()
            .ok();
    }

    if !dns.ipv6_addresses.is_empty() {
        let ipv6_display: Vec<_> = dns.ipv6_addresses.iter().take(3).cloned().collect();
        let suffix = if dns.ipv6_addresses.len() > 3 {
            format!(" (+{} more)", dns.ipv6_addresses.len() - 3)
        } else {
            String::new()
        };
        table.row()
            .element(Text::new("IPv6").styled(style::Style::new().bold().with_font_size(9).with_color(COLOR_PRIMARY)))
            .element(Text::new(format!("{}{}", ipv6_display.join(", "), suffix)).styled(style::Style::new().with_font_size(9).with_color(COLOR_DARK_GRAY)))
            .push()
            .ok();
    }

    if !dns.nameservers.is_empty() {
        table.row()
            .element(Text::new("Nameservers").styled(style::Style::new().bold().with_font_size(9).with_color(COLOR_PRIMARY)))
            .element(Text::new(dns.nameservers.join(", ")).styled(style::Style::new().with_font_size(9).with_color(COLOR_DARK_GRAY)))
            .push()
            .ok();
    }

    let dnssec_text = if dns.dnssec_enabled { "[OK] Enabled" } else { "[--] Not Detected" };
    let dnssec_color = if dns.dnssec_enabled { COLOR_GREEN } else { COLOR_LIGHT_GRAY };
    table.row()
        .element(Text::new("DNSSEC").styled(style::Style::new().bold().with_font_size(9).with_color(COLOR_PRIMARY)))
        .element(Text::new(dnssec_text).styled(style::Style::new().with_font_size(9).with_color(dnssec_color)))
        .push()
        .ok();

    doc.push(table);

    // CAA Records
    if !dns.caa_records.is_empty() {
        doc.push(Break::new(0.3));
        doc.push(
            Paragraph::new("    CAA Records:")
                .styled(style::Style::new().bold().with_font_size(9).with_color(COLOR_PRIMARY))
        );
        for caa in &dns.caa_records {
            doc.push(
                Paragraph::new(format!("      {} {} \"{}\"", caa.flags, caa.tag, caa.value))
                    .styled(style::Style::new().with_font_size(8).with_color(COLOR_DARK_GRAY))
            );
        }
    }

    doc.push(Break::new(0.8));
}

/// Render section header with consistent styling
fn render_section_header(doc: &mut Document, title: &str) {
    doc.push(
        Paragraph::new(title)
            .styled(style::Style::new().bold().with_font_size(12).with_color(COLOR_PRIMARY))
    );
    doc.push(
        Paragraph::new("--------------------------------------------------------------------------------")
            .styled(style::Style::new().with_font_size(6).with_color(COLOR_ACCENT))
    );
    doc.push(Break::new(0.3));
}

/// Render document footer
fn render_footer(doc: &mut Document) {
    doc.push(Break::new(0.5));
    doc.push(
        Paragraph::new("________________________________________________________________________________")
            .styled(style::Style::new().with_color(COLOR_LIGHT_GRAY))
    );
    doc.push(Break::new(0.2));
    doc.push(
        Paragraph::new("Generated by SSL Toolkit  |  https://github.com/russmckendrick/ssl-toolkit")
            .styled(style::Style::new().italic().with_font_size(8).with_color(COLOR_LIGHT_GRAY))
    );
}

/// Truncate string with ellipsis if too long
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len-3])
    }
}
