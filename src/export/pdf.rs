//! PDF report generation for SSL toolkit

use crate::certificate::{CertificateInfo, SecurityGrade};
use crate::error::{Result, SslToolkitError};
use crate::tui::widgets::results::ResultsData;
use chrono::Utc;
use genpdf::{
    elements::{Break, Image, LinearLayout, Paragraph, StyledElement, TableLayout, Text},
    fonts, style, Alignment, Document, Element, Margins, SimplePageDecorator,
};
use std::path::Path;

// Embed a simple placeholder logo as PNG bytes
// In production, you would use: include_bytes!("../../assets/logo.png")
const LOGO_SVG: &[u8] = br#"<svg xmlns="http://www.w3.org/2000/svg" width="120" height="40" viewBox="0 0 120 40">
  <rect width="120" height="40" fill="#0891b2"/>
  <text x="60" y="26" font-family="Arial, sans-serif" font-size="16" font-weight="bold" fill="white" text-anchor="middle">SSL Toolkit</text>
</svg>"#;

/// Export results to PDF
pub fn export_pdf(data: &ResultsData, path: &Path) -> Result<()> {
    // Load default font
    let font_family = fonts::from_files("./", "Liberation", None).unwrap_or_else(|_| {
        // Fallback to built-in font
        fonts::from_files("/usr/share/fonts/truetype/liberation", "LiberationSans", None)
            .unwrap_or_else(|_| {
                fonts::from_files(
                    "/System/Library/Fonts/Supplemental",
                    "Arial Unicode",
                    None,
                )
                .unwrap_or_else(|_| {
                    // Use default genpdf font
                    genpdf::fonts::from_files("", "", None).unwrap_or_else(|_| {
                        panic!("Could not load any font")
                    })
                })
            })
    });

    let mut doc = Document::new(font_family);
    doc.set_title(format!("SSL Certificate Report - {}", data.domain));
    doc.set_minimal_conformance();
    doc.set_line_spacing(1.25);

    // Set page margins
    let mut decorator = SimplePageDecorator::new();
    decorator.set_margins(Margins::trbl(20, 15, 20, 15));
    doc.set_page_decorator(decorator);

    // Try to add logo from SVG
    if let Ok(logo) = render_svg_logo() {
        if let Ok(img) = Image::from_dynamic_image(logo) {
            let scaled = img.with_scale(genpdf::Scale::new(0.5, 0.5));
            doc.push(scaled);
        }
    }

    // Title
    doc.push(
        Paragraph::new(format!("SSL Certificate Report"))
            .styled(style::Style::new().bold().with_font_size(20))
            .aligned(Alignment::Center),
    );

    doc.push(
        Paragraph::new(format!("Domain: {}:{}", data.domain, data.port))
            .styled(style::Style::new().with_font_size(14))
            .aligned(Alignment::Center),
    );

    doc.push(
        Paragraph::new(format!(
            "Generated: {}",
            Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        ))
        .styled(style::Style::new().with_font_size(10).with_color(style::Color::Rgb(128, 128, 128)))
        .aligned(Alignment::Center),
    );

    doc.push(Break::new(1.5));

    // Security Grade Section
    if let Some(ref grade) = data.grade {
        add_grade_section(&mut doc, grade);
        doc.push(Break::new(1.0));
    }

    // Certificate Details Section
    if let Some(ref chain) = data.chain {
        if let Some(cert) = chain.leaf() {
            add_certificate_section(&mut doc, cert);
            doc.push(Break::new(1.0));
        }

        // Chain Section
        add_chain_section(&mut doc, chain);
        doc.push(Break::new(1.0));
    }

    // DNS Section
    if let Some(ref dns) = data.dns {
        add_dns_section(&mut doc, dns);
    }

    // Save document
    doc.render_to_file(path)
        .map_err(|e| SslToolkitError::PdfGeneration(e.to_string()))?;

    Ok(())
}

/// Render SVG logo to a dynamic image
fn render_svg_logo() -> Result<image::DynamicImage> {
    use resvg::tiny_skia;
    use resvg::usvg;

    let opts = usvg::Options::default();
    let tree = usvg::Tree::from_data(LOGO_SVG, &opts)
        .map_err(|e| SslToolkitError::PdfGeneration(format!("Failed to parse SVG: {}", e)))?;

    let size = tree.size();
    let width = size.width() as u32;
    let height = size.height() as u32;

    let mut pixmap = tiny_skia::Pixmap::new(width, height).ok_or_else(|| {
        SslToolkitError::PdfGeneration("Failed to create pixmap".to_string())
    })?;

    resvg::render(&tree, tiny_skia::Transform::default(), &mut pixmap.as_mut());

    // Convert to image::DynamicImage
    let img = image::RgbaImage::from_raw(width, height, pixmap.data().to_vec()).ok_or_else(|| {
        SslToolkitError::PdfGeneration("Failed to create image".to_string())
    })?;

    Ok(image::DynamicImage::ImageRgba8(img))
}

/// Add security grade section to document
fn add_grade_section(doc: &mut Document, grade: &SecurityGrade) {
    doc.push(
        Paragraph::new("Security Grade")
            .styled(style::Style::new().bold().with_font_size(14))
    );

    doc.push(Break::new(0.5));

    let grade_color = match grade.grade {
        'A' => style::Color::Rgb(34, 197, 94),  // green
        'B' => style::Color::Rgb(6, 182, 212),   // cyan
        'C' => style::Color::Rgb(234, 179, 8),   // yellow
        'D' => style::Color::Rgb(249, 115, 22),  // orange
        _ => style::Color::Rgb(239, 68, 68),     // red
    };

    doc.push(
        Paragraph::new(format!("Grade: {} ({}%)", grade.display(), grade.score))
            .styled(style::Style::new().bold().with_font_size(16).with_color(grade_color))
    );

    doc.push(Break::new(0.5));

    // Grade factors table
    let mut table = TableLayout::new(vec![3, 5, 1, 1]);
    table.set_cell_decorator(genpdf::elements::FrameCellDecorator::new(true, true, false));

    // Header
    table
        .row()
        .element(Text::new("Factor").styled(style::Style::new().bold()))
        .element(Text::new("Description").styled(style::Style::new().bold()))
        .element(Text::new("Points").styled(style::Style::new().bold()))
        .element(Text::new("Max").styled(style::Style::new().bold()))
        .push()
        .ok();

    for factor in &grade.factors {
        let status_symbol = match factor.status {
            crate::certificate::security::FactorStatus::Pass => "[OK]",
            crate::certificate::security::FactorStatus::Warning => "[!]",
            crate::certificate::security::FactorStatus::Fail => "[X]",
            crate::certificate::security::FactorStatus::NotApplicable => "[-]",
        };

        table
            .row()
            .element(Text::new(format!("{} {}", status_symbol, factor.name)))
            .element(Text::new(&factor.description))
            .element(Text::new(format!("{}", factor.points)))
            .element(Text::new(format!("{}", factor.max_points)))
            .push()
            .ok();
    }

    doc.push(table);
}

/// Add certificate details section to document
fn add_certificate_section(doc: &mut Document, cert: &CertificateInfo) {
    doc.push(
        Paragraph::new("Certificate Details")
            .styled(style::Style::new().bold().with_font_size(14))
    );

    doc.push(Break::new(0.5));

    let mut table = TableLayout::new(vec![2, 5]);
    table.set_cell_decorator(genpdf::elements::FrameCellDecorator::new(true, true, false));

    // Subject
    table
        .row()
        .element(Text::new("Subject").styled(style::Style::new().bold()))
        .element(Text::new(
            cert.subject.common_name.clone().unwrap_or_default(),
        ))
        .push()
        .ok();

    // Issuer
    table
        .row()
        .element(Text::new("Issuer").styled(style::Style::new().bold()))
        .element(Text::new(
            cert.issuer.common_name.clone().unwrap_or_default(),
        ))
        .push()
        .ok();

    // Valid From
    table
        .row()
        .element(Text::new("Valid From").styled(style::Style::new().bold()))
        .element(Text::new(
            cert.not_before.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        ))
        .push()
        .ok();

    // Valid Until
    table
        .row()
        .element(Text::new("Valid Until").styled(style::Style::new().bold()))
        .element(Text::new(
            cert.not_after.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        ))
        .push()
        .ok();

    // Days Until Expiry
    let expiry_text = if cert.days_until_expiry < 0 {
        format!("EXPIRED ({} days ago)", cert.days_until_expiry.abs())
    } else {
        format!("{} days", cert.days_until_expiry)
    };
    table
        .row()
        .element(Text::new("Days Until Expiry").styled(style::Style::new().bold()))
        .element(Text::new(expiry_text))
        .push()
        .ok();

    // Serial Number
    table
        .row()
        .element(Text::new("Serial Number").styled(style::Style::new().bold()))
        .element(Text::new(&cert.serial_number))
        .push()
        .ok();

    // Key Algorithm
    table
        .row()
        .element(Text::new("Key Algorithm").styled(style::Style::new().bold()))
        .element(Text::new(cert.key_algorithm.to_string()))
        .push()
        .ok();

    // Signature Algorithm
    table
        .row()
        .element(Text::new("Signature Algorithm").styled(style::Style::new().bold()))
        .element(Text::new(&cert.signature_algorithm))
        .push()
        .ok();

    // Trust Status
    table
        .row()
        .element(Text::new("Trust Status").styled(style::Style::new().bold()))
        .element(Text::new(cert.trust_status.to_string()))
        .push()
        .ok();

    doc.push(table);

    // SANs section
    if !cert.subject_alt_names.is_empty() {
        doc.push(Break::new(0.5));
        doc.push(
            Paragraph::new(format!("Subject Alternative Names ({}):", cert.subject_alt_names.len()))
                .styled(style::Style::new().bold())
        );

        for san in &cert.subject_alt_names {
            doc.push(Paragraph::new(format!("  - {}", san)));
        }
    }
}

/// Add chain section to document
fn add_chain_section(doc: &mut Document, chain: &crate::certificate::CertificateChain) {
    doc.push(
        Paragraph::new("Certificate Chain")
            .styled(style::Style::new().bold().with_font_size(14))
    );

    doc.push(Break::new(0.5));

    doc.push(Paragraph::new(format!("Chain Length: {}", chain.chain_length)));
    doc.push(Paragraph::new(format!(
        "Complete: {}",
        if chain.is_complete { "Yes" } else { "No" }
    )));
    doc.push(Paragraph::new(format!(
        "Root in Trust Store: {}",
        if chain.root_in_store { "Yes" } else { "Unknown" }
    )));

    doc.push(Break::new(0.5));

    for (i, cert) in chain.certificates.iter().enumerate() {
        let role = if i == 0 {
            "Leaf"
        } else if i == chain.certificates.len() - 1 {
            "Root"
        } else {
            "Intermediate"
        };

        doc.push(Paragraph::new(format!(
            "{}. [{}] {}",
            i + 1,
            role,
            cert.subject.common_name.clone().unwrap_or_default()
        )));
    }
}

/// Add DNS section to document
fn add_dns_section(doc: &mut Document, dns: &crate::dns::DnsInfo) {
    doc.push(
        Paragraph::new("DNS Information")
            .styled(style::Style::new().bold().with_font_size(14))
    );

    doc.push(Break::new(0.5));

    // IPv4
    if !dns.ipv4_addresses.is_empty() {
        doc.push(Paragraph::new("IPv4 Addresses:").styled(style::Style::new().bold()));
        for ip in &dns.ipv4_addresses {
            doc.push(Paragraph::new(format!("  - {}", ip)));
        }
        doc.push(Break::new(0.3));
    }

    // IPv6
    if !dns.ipv6_addresses.is_empty() {
        doc.push(Paragraph::new("IPv6 Addresses:").styled(style::Style::new().bold()));
        for ip in &dns.ipv6_addresses {
            doc.push(Paragraph::new(format!("  - {}", ip)));
        }
        doc.push(Break::new(0.3));
    }

    // Nameservers
    if !dns.nameservers.is_empty() {
        doc.push(Paragraph::new("Nameservers:").styled(style::Style::new().bold()));
        for ns in &dns.nameservers {
            doc.push(Paragraph::new(format!("  - {}", ns)));
        }
        doc.push(Break::new(0.3));
    }

    // DNSSEC
    doc.push(Paragraph::new(format!(
        "DNSSEC: {}",
        if dns.dnssec_enabled { "Enabled" } else { "Not detected" }
    )));

    // CAA Records
    if !dns.caa_records.is_empty() {
        doc.push(Break::new(0.3));
        doc.push(Paragraph::new("CAA Records:").styled(style::Style::new().bold()));
        for caa in &dns.caa_records {
            doc.push(Paragraph::new(format!(
                "  - {} {} \"{}\"",
                caa.flags, caa.tag, caa.value
            )));
        }
    }
}
