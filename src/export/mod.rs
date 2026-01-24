//! Export functionality for SSL toolkit results
//!
//! Supports exporting to:
//! - PDF reports
//! - PEM certificate chains
//! - iCal calendar files with reminders

use crate::certificate::CertificateChain;
use crate::dns::DnsInfo;
use crate::error::{Result, SslToolkitError};
use crate::tui::widgets::results::ResultsData;
use chrono::{DateTime, Duration, Utc};
use std::path::Path;
use uuid::Uuid;

pub mod pdf;

/// Result of an export operation
#[derive(Debug, Clone, PartialEq)]
pub struct ExportResult {
    pub export_type: ExportType,
    pub path: String,
    pub success: bool,
    pub error: Option<String>,
}

/// Type of export
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ExportType {
    Pdf,
    Pem,
    ICal,
}

impl ExportType {
    pub fn label(&self) -> &'static str {
        match self {
            ExportType::Pdf => "PDF Report",
            ExportType::Pem => "Certificate Chain",
            ExportType::ICal => "Calendar Reminder",
        }
    }
}

/// Generate filename for export
pub fn generate_filename(domain: &str, export_type: ExportType) -> String {
    let safe_domain = domain.replace('.', "_").replace(':', "_");
    let date = Utc::now().format("%Y%m%d").to_string();

    match export_type {
        ExportType::Pdf => format!("{}_ssl_report_{}.pdf", safe_domain, date),
        ExportType::Pem => format!("{}_chain.pem", safe_domain),
        ExportType::ICal => format!("{}_ssl_expiry.ics", safe_domain),
    }
}

/// Export certificate chain as PEM file
pub fn export_pem(chain: &CertificateChain, path: &Path) -> Result<()> {
    let mut pem_content = String::new();

    for cert in &chain.certificates {
        if let Some(ref raw_pem) = cert.raw_pem {
            pem_content.push_str(raw_pem);
            pem_content.push('\n');
        }
    }

    if pem_content.is_empty() {
        return Err(SslToolkitError::Export(
            "No PEM data available in certificate chain".to_string(),
        ));
    }

    std::fs::write(path, pem_content).map_err(|e| SslToolkitError::Export(e.to_string()))?;

    Ok(())
}

/// Generate iCal file with SSL certificate expiry reminders
/// Creates events at 30, 15, and 5 days before expiry
pub fn generate_ical(domain: &str, expiry_date: DateTime<Utc>) -> Result<String> {
    let mut ical = String::new();

    // iCal header
    ical.push_str("BEGIN:VCALENDAR\r\n");
    ical.push_str("VERSION:2.0\r\n");
    ical.push_str("PRODID:-//SSL Toolkit//SSL Certificate Reminder//EN\r\n");
    ical.push_str("CALSCALE:GREGORIAN\r\n");
    ical.push_str("METHOD:PUBLISH\r\n");

    // Create reminder events at 30, 15, and 5 days before expiry
    let reminder_days = [30, 15, 5];

    for days in reminder_days {
        let reminder_date = expiry_date - Duration::days(days);
        let event = create_reminder_event(domain, &expiry_date, &reminder_date, days)?;
        ical.push_str(&event);
    }

    // Also create the actual expiry event
    let expiry_event = create_expiry_event(domain, &expiry_date)?;
    ical.push_str(&expiry_event);

    // iCal footer
    ical.push_str("END:VCALENDAR\r\n");

    Ok(ical)
}

/// Create a reminder event for the calendar
fn create_reminder_event(
    domain: &str,
    expiry_date: &DateTime<Utc>,
    reminder_date: &DateTime<Utc>,
    days_before: i64,
) -> Result<String> {
    let uid = Uuid::new_v4();
    let now = Utc::now();

    let urgency = match days_before {
        30 => "NOTICE",
        15 => "WARNING",
        5 => "CRITICAL",
        _ => "REMINDER",
    };

    let mut event = String::new();

    event.push_str("BEGIN:VEVENT\r\n");
    event.push_str(&format!("UID:{}-{}@ssl-toolkit\r\n", uid, days_before));
    event.push_str(&format!(
        "DTSTAMP:{}\r\n",
        now.format("%Y%m%dT%H%M%SZ")
    ));
    event.push_str(&format!(
        "DTSTART:{}\r\n",
        reminder_date.format("%Y%m%dT090000Z")
    ));
    event.push_str(&format!(
        "DTEND:{}\r\n",
        reminder_date.format("%Y%m%dT100000Z")
    ));
    event.push_str(&format!(
        "SUMMARY:[{}] SSL Certificate Expiry - {} days - {}\r\n",
        urgency, days_before, domain
    ));
    event.push_str(&format!(
        "DESCRIPTION:The SSL certificate for {} will expire in {} days on {}.\\n\\nPlease renew the certificate before expiry to avoid service disruption.\r\n",
        domain,
        days_before,
        expiry_date.format("%Y-%m-%d %H:%M UTC")
    ));
    event.push_str("CATEGORIES:SSL,CERTIFICATE,SECURITY\r\n");
    event.push_str(&format!("PRIORITY:{}\r\n", match days_before {
        5 => 1,
        15 => 3,
        _ => 5,
    }));

    // Add alarm
    event.push_str("BEGIN:VALARM\r\n");
    event.push_str("ACTION:DISPLAY\r\n");
    event.push_str(&format!(
        "DESCRIPTION:SSL Certificate for {} expires in {} days\r\n",
        domain, days_before
    ));
    event.push_str("TRIGGER:-PT1H\r\n");
    event.push_str("END:VALARM\r\n");

    event.push_str("END:VEVENT\r\n");

    Ok(event)
}

/// Create the actual expiry event
fn create_expiry_event(domain: &str, expiry_date: &DateTime<Utc>) -> Result<String> {
    let uid = Uuid::new_v4();
    let now = Utc::now();

    let mut event = String::new();

    event.push_str("BEGIN:VEVENT\r\n");
    event.push_str(&format!("UID:{}-expiry@ssl-toolkit\r\n", uid));
    event.push_str(&format!(
        "DTSTAMP:{}\r\n",
        now.format("%Y%m%dT%H%M%SZ")
    ));
    event.push_str(&format!(
        "DTSTART:{}\r\n",
        expiry_date.format("%Y%m%dT%H%M%SZ")
    ));
    event.push_str(&format!(
        "DTEND:{}\r\n",
        (*expiry_date + Duration::hours(1)).format("%Y%m%dT%H%M%SZ")
    ));
    event.push_str(&format!(
        "SUMMARY:SSL CERTIFICATE EXPIRED - {}\r\n",
        domain
    ));
    event.push_str(&format!(
        "DESCRIPTION:The SSL certificate for {} has expired.\\n\\nIMPORTATE: Your website or service may be inaccessible or showing security warnings.\r\n",
        domain
    ));
    event.push_str("CATEGORIES:SSL,CERTIFICATE,SECURITY,EXPIRED\r\n");
    event.push_str("PRIORITY:1\r\n");
    event.push_str("STATUS:CONFIRMED\r\n");

    // Add alarm at the time of expiry
    event.push_str("BEGIN:VALARM\r\n");
    event.push_str("ACTION:DISPLAY\r\n");
    event.push_str(&format!(
        "DESCRIPTION:SSL Certificate for {} has expired!\r\n",
        domain
    ));
    event.push_str("TRIGGER:PT0M\r\n");
    event.push_str("END:VALARM\r\n");

    event.push_str("END:VEVENT\r\n");

    Ok(event)
}

/// Export iCal file
pub fn export_ical(domain: &str, expiry_date: DateTime<Utc>, path: &Path) -> Result<()> {
    let ical_content = generate_ical(domain, expiry_date)?;
    std::fs::write(path, ical_content).map_err(|e| SslToolkitError::Export(e.to_string()))?;
    Ok(())
}

/// Export all formats
pub fn export_all(
    data: &ResultsData,
    base_path: &Path,
) -> Vec<ExportResult> {
    let mut results = Vec::new();

    // Export PDF
    let pdf_filename = generate_filename(&data.domain, ExportType::Pdf);
    let pdf_path = base_path.join(&pdf_filename);
    let pdf_result = match pdf::export_pdf(data, &pdf_path) {
        Ok(()) => ExportResult {
            export_type: ExportType::Pdf,
            path: pdf_path.display().to_string(),
            success: true,
            error: None,
        },
        Err(e) => ExportResult {
            export_type: ExportType::Pdf,
            path: pdf_path.display().to_string(),
            success: false,
            error: Some(e.to_string()),
        },
    };
    results.push(pdf_result);

    // Export PEM
    if let Some(ref chain) = data.chain {
        let pem_filename = generate_filename(&data.domain, ExportType::Pem);
        let pem_path = base_path.join(&pem_filename);
        let pem_result = match export_pem(chain, &pem_path) {
            Ok(()) => ExportResult {
                export_type: ExportType::Pem,
                path: pem_path.display().to_string(),
                success: true,
                error: None,
            },
            Err(e) => ExportResult {
                export_type: ExportType::Pem,
                path: pem_path.display().to_string(),
                success: false,
                error: Some(e.to_string()),
            },
        };
        results.push(pem_result);
    }

    // Export iCal
    if let Some(ref chain) = data.chain {
        if let Some(leaf) = chain.leaf() {
            let ical_filename = generate_filename(&data.domain, ExportType::ICal);
            let ical_path = base_path.join(&ical_filename);
            let ical_result = match export_ical(&data.domain, leaf.not_after, &ical_path) {
                Ok(()) => ExportResult {
                    export_type: ExportType::ICal,
                    path: ical_path.display().to_string(),
                    success: true,
                    error: None,
                },
                Err(e) => ExportResult {
                    export_type: ExportType::ICal,
                    path: ical_path.display().to_string(),
                    success: false,
                    error: Some(e.to_string()),
                },
            };
            results.push(ical_result);
        }
    }

    results
}

/// Export single format
pub fn export_single(
    data: &ResultsData,
    base_path: &Path,
    export_type: ExportType,
) -> ExportResult {
    let filename = generate_filename(&data.domain, export_type);
    let full_path = base_path.join(&filename);

    match export_type {
        ExportType::Pdf => {
            match pdf::export_pdf(data, &full_path) {
                Ok(()) => ExportResult {
                    export_type,
                    path: full_path.display().to_string(),
                    success: true,
                    error: None,
                },
                Err(e) => ExportResult {
                    export_type,
                    path: full_path.display().to_string(),
                    success: false,
                    error: Some(e.to_string()),
                },
            }
        }
        ExportType::Pem => {
            if let Some(ref chain) = data.chain {
                match export_pem(chain, &full_path) {
                    Ok(()) => ExportResult {
                        export_type,
                        path: full_path.display().to_string(),
                        success: true,
                        error: None,
                    },
                    Err(e) => ExportResult {
                        export_type,
                        path: full_path.display().to_string(),
                        success: false,
                        error: Some(e.to_string()),
                    },
                }
            } else {
                ExportResult {
                    export_type,
                    path: full_path.display().to_string(),
                    success: false,
                    error: Some("No certificate chain available".to_string()),
                }
            }
        }
        ExportType::ICal => {
            if let Some(ref chain) = data.chain {
                if let Some(leaf) = chain.leaf() {
                    match export_ical(&data.domain, leaf.not_after, &full_path) {
                        Ok(()) => ExportResult {
                            export_type,
                            path: full_path.display().to_string(),
                            success: true,
                            error: None,
                        },
                        Err(e) => ExportResult {
                            export_type,
                            path: full_path.display().to_string(),
                            success: false,
                            error: Some(e.to_string()),
                        },
                    }
                } else {
                    ExportResult {
                        export_type,
                        path: full_path.display().to_string(),
                        success: false,
                        error: Some("No leaf certificate available".to_string()),
                    }
                }
            } else {
                ExportResult {
                    export_type,
                    path: full_path.display().to_string(),
                    success: false,
                    error: Some("No certificate chain available".to_string()),
                }
            }
        }
    }
}
