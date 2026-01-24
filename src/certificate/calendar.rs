//! iCal calendar generation for certificate expiry reminders

use crate::certificate::info::CertificateInfo;
use chrono::{Duration, Utc};
use std::fs::File;
use std::io::Write;
use std::path::Path;

/// Generate an iCal file for certificate expiry reminder
pub fn generate_ical_reminder(
    cert: &CertificateInfo,
    domain: &str,
    days_before: i64,
) -> String {
    let now = Utc::now();
    let uid = format!(
        "ssl-toolkit-{}@{}",
        cert.serial_number.replace(":", ""),
        domain
    );

    // Calculate reminder date (days before expiry)
    let reminder_date = cert.not_after - Duration::days(days_before);

    let summary = format!("SSL Certificate Expiry: {}", domain);
    let description = format!(
        "The SSL certificate for {} will expire on {}.\n\n\
         Certificate Details:\n\
         - Subject: {}\n\
         - Issuer: {}\n\
         - Serial: {}\n\
         - SHA256 Fingerprint: {}",
        domain,
        cert.not_after.format("%Y-%m-%d %H:%M:%S UTC"),
        cert.subject,
        cert.issuer,
        cert.serial_number,
        cert.fingerprint_sha256
    );

    // Format dates for iCal (YYYYMMDDTHHMMSSZ)
    let dtstart = reminder_date.format("%Y%m%dT090000Z");
    let dtend = reminder_date.format("%Y%m%dT100000Z");
    let dtstamp = now.format("%Y%m%dT%H%M%SZ");
    let expiry_date = cert.not_after.format("%Y%m%dT%H%M%SZ");

    format!(
        "BEGIN:VCALENDAR\r\n\
         VERSION:2.0\r\n\
         PRODID:-//SSL Toolkit//Certificate Expiry Reminder//EN\r\n\
         CALSCALE:GREGORIAN\r\n\
         METHOD:PUBLISH\r\n\
         BEGIN:VEVENT\r\n\
         UID:{}\r\n\
         DTSTAMP:{}\r\n\
         DTSTART:{}\r\n\
         DTEND:{}\r\n\
         SUMMARY:{}\r\n\
         DESCRIPTION:{}\r\n\
         CATEGORIES:SSL,Certificate,Security\r\n\
         PRIORITY:1\r\n\
         STATUS:CONFIRMED\r\n\
         BEGIN:VALARM\r\n\
         ACTION:DISPLAY\r\n\
         DESCRIPTION:SSL Certificate for {} expires in {} days\r\n\
         TRIGGER:-P1D\r\n\
         END:VALARM\r\n\
         BEGIN:VALARM\r\n\
         ACTION:DISPLAY\r\n\
         DESCRIPTION:SSL Certificate for {} expires in {} days\r\n\
         TRIGGER:-P7D\r\n\
         END:VALARM\r\n\
         END:VEVENT\r\n\
         BEGIN:VEVENT\r\n\
         UID:{}-expiry\r\n\
         DTSTAMP:{}\r\n\
         DTSTART:{}\r\n\
         DTEND:{}\r\n\
         SUMMARY:SSL Certificate EXPIRED: {}\r\n\
         DESCRIPTION:The SSL certificate for {} has EXPIRED!\r\n\
         CATEGORIES:SSL,Certificate,Security,Expired\r\n\
         PRIORITY:1\r\n\
         STATUS:CONFIRMED\r\n\
         END:VEVENT\r\n\
         END:VCALENDAR\r\n",
        uid,
        dtstamp,
        dtstart,
        dtend,
        summary,
        escape_ical_text(&description),
        domain,
        days_before,
        domain,
        days_before,
        uid,
        dtstamp,
        expiry_date,
        expiry_date,
        domain,
        domain
    )
}

/// Save iCal content to a file
pub fn save_ical_file(content: &str, path: &Path) -> std::io::Result<()> {
    let mut file = File::create(path)?;
    file.write_all(content.as_bytes())?;
    Ok(())
}

/// Escape special characters for iCal format
fn escape_ical_text(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace(';', "\\;")
        .replace(',', "\\,")
        .replace('\n', "\\n")
        .replace('\r', "")
}

/// Generate filename for iCal file
pub fn generate_ical_filename(domain: &str) -> String {
    let safe_domain = domain.replace('.', "_").replace(':', "_");
    format!("{}_ssl_expiry.ics", safe_domain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificate::info::{DistinguishedName, KeyAlgorithm, TrustStatus};
    use chrono::TimeZone;

    fn create_test_cert() -> CertificateInfo {
        CertificateInfo {
            version: 3,
            serial_number: "01:02:03:04:05".to_string(),
            subject: DistinguishedName {
                common_name: Some("example.com".to_string()),
                organization: Some("Example Inc".to_string()),
                ..Default::default()
            },
            issuer: DistinguishedName {
                common_name: Some("Test CA".to_string()),
                organization: Some("Test CA Inc".to_string()),
                ..Default::default()
            },
            not_before: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            not_after: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
            days_until_expiry: 365,
            signature_algorithm: "SHA256withRSA".to_string(),
            key_algorithm: KeyAlgorithm::Rsa(2048),
            key_size: 2048,
            subject_alt_names: vec!["example.com".to_string(), "www.example.com".to_string()],
            is_validated: true,
            validation_error: None,
            trust_status: TrustStatus::Trusted,
            ocsp_status: None,
            ocsp_stapling: false,
            ct_logged: true,
            is_ca: false,
            fingerprint_sha256: "abc123".to_string(),
            fingerprint_sha1: "def456".to_string(),
            authority_info_access: None,
            crl_distribution_points: vec![],
            certificate_policies: vec![],
            raw_pem: None,
        }
    }

    #[test]
    fn test_generate_ical() {
        let cert = create_test_cert();
        let ical = generate_ical_reminder(&cert, "example.com", 30);

        assert!(ical.contains("BEGIN:VCALENDAR"));
        assert!(ical.contains("END:VCALENDAR"));
        assert!(ical.contains("SSL Certificate Expiry: example.com"));
        assert!(ical.contains("BEGIN:VALARM"));
    }

    #[test]
    fn test_escape_ical_text() {
        assert_eq!(escape_ical_text("test;text"), "test\\;text");
        assert_eq!(escape_ical_text("test,text"), "test\\,text");
        assert_eq!(escape_ical_text("test\ntext"), "test\\ntext");
    }

    #[test]
    fn test_generate_filename() {
        assert_eq!(generate_ical_filename("example.com"), "example_com_ssl_expiry.ics");
        assert_eq!(generate_ical_filename("sub.example.com"), "sub_example_com_ssl_expiry.ics");
    }
}
