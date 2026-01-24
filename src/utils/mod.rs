//! Utility functions for ssl-toolkit

use crate::error::{Result, SslToolkitError};

/// Clean and normalize a domain name
pub fn clean_domain(input: &str) -> Result<String> {
    let mut domain = input.trim().to_lowercase();

    // Remove protocol prefix
    if let Some(stripped) = domain.strip_prefix("https://") {
        domain = stripped.to_string();
    } else if let Some(stripped) = domain.strip_prefix("http://") {
        domain = stripped.to_string();
    }

    // Remove path
    if let Some(idx) = domain.find('/') {
        domain = domain[..idx].to_string();
    }

    // Remove port
    if let Some(idx) = domain.rfind(':') {
        // Make sure it's not part of IPv6
        if !domain.contains('[') {
            domain = domain[..idx].to_string();
        }
    }

    // Remove trailing dot
    if domain.ends_with('.') {
        domain.pop();
    }

    // Validate domain
    if domain.is_empty() {
        return Err(SslToolkitError::InvalidDomain("Empty domain".to_string()));
    }

    // Check for valid characters
    if !domain
        .chars()
        .all(|c| c.is_alphanumeric() || c == '.' || c == '-')
    {
        // Try punycode conversion for internationalized domains
        match idna::domain_to_ascii(&domain) {
            Ok(ascii) => domain = ascii,
            Err(_) => {
                return Err(SslToolkitError::InvalidDomain(format!(
                    "Invalid domain: {}",
                    domain
                )))
            }
        }
    }

    Ok(domain)
}

/// Convert domain to punycode if needed
pub fn to_punycode(domain: &str) -> Result<String> {
    idna::domain_to_ascii(domain)
        .map_err(|e| SslToolkitError::InvalidDomain(format!("Punycode conversion failed: {:?}", e)))
}

/// Convert punycode back to unicode
pub fn from_punycode(domain: &str) -> String {
    idna::domain_to_unicode(domain).0
}

/// Extract the base domain from a full domain name
pub fn extract_base_domain(domain: &str) -> String {
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() <= 2 {
        domain.to_string()
    } else {
        // Handle multi-part TLDs like co.uk
        let known_multi_tlds = ["co.uk", "com.au", "org.uk", "net.au", "co.nz", "com.br"];
        let last_two = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);

        if known_multi_tlds.contains(&last_two.as_str()) && parts.len() > 2 {
            format!(
                "{}.{}.{}",
                parts[parts.len() - 3],
                parts[parts.len() - 2],
                parts[parts.len() - 1]
            )
        } else {
            last_two
        }
    }
}

/// Format bytes into human-readable size
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Format duration in a human-readable way
pub fn format_duration(days: i64) -> String {
    if days < 0 {
        let abs_days = days.abs();
        if abs_days == 1 {
            "1 day ago".to_string()
        } else if abs_days < 30 {
            format!("{} days ago", abs_days)
        } else if abs_days < 365 {
            let months = abs_days / 30;
            if months == 1 {
                "1 month ago".to_string()
            } else {
                format!("{} months ago", months)
            }
        } else {
            let years = abs_days / 365;
            if years == 1 {
                "1 year ago".to_string()
            } else {
                format!("{} years ago", years)
            }
        }
    } else if days == 0 {
        "today".to_string()
    } else if days == 1 {
        "1 day".to_string()
    } else if days < 30 {
        format!("{} days", days)
    } else if days < 365 {
        let months = days / 30;
        if months == 1 {
            "1 month".to_string()
        } else {
            format!("{} months", months)
        }
    } else {
        let years = days / 365;
        if years == 1 {
            "1 year".to_string()
        } else {
            format!("{} years", years)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_domain() {
        assert_eq!(clean_domain("example.com").unwrap(), "example.com");
        assert_eq!(
            clean_domain("https://example.com").unwrap(),
            "example.com"
        );
        assert_eq!(
            clean_domain("https://example.com/path").unwrap(),
            "example.com"
        );
        assert_eq!(
            clean_domain("example.com:443").unwrap(),
            "example.com"
        );
        assert_eq!(
            clean_domain("  EXAMPLE.COM  ").unwrap(),
            "example.com"
        );
    }

    #[test]
    fn test_extract_base_domain() {
        assert_eq!(extract_base_domain("www.example.com"), "example.com");
        assert_eq!(extract_base_domain("example.com"), "example.com");
        assert_eq!(extract_base_domain("sub.domain.example.co.uk"), "example.co.uk");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(0), "today");
        assert_eq!(format_duration(1), "1 day");
        assert_eq!(format_duration(15), "15 days");
        assert_eq!(format_duration(45), "1 month");
        assert_eq!(format_duration(400), "1 year");
        assert_eq!(format_duration(-1), "1 day ago");
    }
}
