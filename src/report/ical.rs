//! iCal generation for certificate expiry reminders
//!
//! Generates RFC 5545 compliant iCal files with reminder events.

use crate::models::CertificateInfo;
use chrono::{Duration, Utc};
use icalendar::{Alarm, Calendar, Component, Event, EventLike, Trigger};

/// iCal generator for certificate expiry reminders
pub struct IcalGenerator;

impl IcalGenerator {
    /// Generate an iCal file with expiry reminders
    pub fn generate(domain: &str, cert: &CertificateInfo) -> String {
        let mut calendar = Calendar::new()
            .name(&format!("SSL Certificate Expiry - {}", domain))
            .done();

        // Main expiry event
        let expiry_event = Event::new()
            .summary(&format!("SSL Certificate Expires: {}", domain))
            .description(&format!(
                "The SSL/TLS certificate for {} expires on this date.\n\nSubject: {}\nIssuer: {}",
                domain, cert.subject, cert.issuer
            ))
            .starts(cert.not_after)
            .ends(cert.not_after + Duration::hours(1))
            .done();

        calendar.push(expiry_event);

        // Add reminder events at various intervals
        let reminder_days = [30, 15, 7, 1];

        for days in reminder_days {
            let reminder_date = cert.not_after - Duration::days(days);

            // Only add reminder if it's in the future
            if reminder_date > Utc::now() {
                let urgency = if days <= 7 { "URGENT: " } else { "" };

                let reminder_event = Event::new()
                    .summary(&format!(
                        "{}SSL Certificate Expires in {} days: {}",
                        urgency, days, domain
                    ))
                    .description(&format!(
                        "The SSL/TLS certificate for {} will expire in {} days.\n\n\
                        Please renew the certificate before it expires.\n\n\
                        Subject: {}\n\
                        Issuer: {}\n\
                        Expires: {}",
                        domain,
                        days,
                        cert.subject,
                        cert.issuer,
                        cert.not_after.format("%Y-%m-%d %H:%M:%S UTC")
                    ))
                    .starts(reminder_date)
                    .ends(reminder_date + Duration::hours(1))
                    .alarm(Alarm::display(
                        &format!("SSL Certificate for {} expires in {} days!", domain, days),
                        Trigger::before_start(chrono::Duration::zero()),
                    ))
                    .done();

                calendar.push(reminder_event);
            }
        }

        calendar.to_string()
    }

    /// Generate a minimal iCal with just the expiry date
    pub fn generate_simple(domain: &str, cert: &CertificateInfo) -> String {
        let calendar = Calendar::new()
            .name(&format!("SSL Certificate Expiry - {}", domain))
            .push(
                Event::new()
                    .summary(&format!("SSL Certificate Expires: {}", domain))
                    .starts(cert.not_after)
                    .ends(cert.not_after + Duration::hours(1))
                    .done(),
            )
            .done();

        calendar.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_generate_ical() {
        let cert = CertificateInfo {
            subject: "CN=example.com".to_string(),
            issuer: "CN=Test CA".to_string(),
            serial: "01".to_string(),
            thumbprint: "AA:BB:CC".to_string(),
            not_before: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            not_after: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
            san: vec!["example.com".to_string()],
            public_key_algorithm: "RSA".to_string(),
            public_key_size: 2048,
            signature_algorithm: "SHA256withRSA".to_string(),
            is_self_signed: false,
            is_ca: false,
            version: 3,
            key_usage: vec![],
            extended_key_usage: vec![],
            raw_der: vec![],
        };

        let ical = IcalGenerator::generate("example.com", &cert);
        assert!(ical.contains("BEGIN:VCALENDAR"));
        assert!(ical.contains("SSL Certificate Expires"));
        assert!(ical.contains("END:VCALENDAR"));
    }
}
