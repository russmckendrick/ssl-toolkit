//! Message templates for user-facing text
//!
//! All user-visible strings are defined here for easy localization and customization.

use crate::utils::ConfigError;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

/// Screen names for header display
#[derive(Debug, Clone, Deserialize)]
pub struct ScreenNames {
    pub welcome: String,
    pub domain_input: String,
    pub dns_results: String,
    pub ip_selection: String,
    pub port_selection: String,
    pub running: String,
    pub results: String,
    pub save_prompt: String,
    pub complete: String,
    pub error: String,
}

impl Default for ScreenNames {
    fn default() -> Self {
        Self {
            welcome: "Welcome".to_string(),
            domain_input: "Enter Domain".to_string(),
            dns_results: "DNS Results".to_string(),
            ip_selection: "Select IPs".to_string(),
            port_selection: "Select Port".to_string(),
            running: "Running Checks".to_string(),
            results: "Results".to_string(),
            save_prompt: "Save Report".to_string(),
            complete: "Complete".to_string(),
            error: "Error".to_string(),
        }
    }
}

/// Header messages for consistent TUI chrome
#[derive(Debug, Clone, Deserialize)]
pub struct HeaderMessages {
    pub app_name: String,
    pub separator: String,
    #[serde(default)]
    pub screen_names: ScreenNames,
}

impl Default for HeaderMessages {
    fn default() -> Self {
        Self {
            app_name: "SSL Toolkit".to_string(),
            separator: " │ ".to_string(),
            screen_names: ScreenNames::default(),
        }
    }
}

/// Footer messages for navigation hints
#[derive(Debug, Clone, Deserialize)]
pub struct FooterMessages {
    pub nav_separator: String,
    pub back_hint: String,
    pub next_hint: String,
}

impl Default for FooterMessages {
    fn default() -> Self {
        Self {
            nav_separator: " │ ".to_string(),
            back_hint: "← Back".to_string(),
            next_hint: "Next →".to_string(),
        }
    }
}

/// Welcome screen messages
#[derive(Debug, Clone, Deserialize)]
pub struct WelcomeMessages {
    pub title: String,
    pub subtitle: String,
    pub prompt: String,
    pub hint: String,
}

impl Default for WelcomeMessages {
    fn default() -> Self {
        Self {
            title: "SSL Toolkit".to_string(),
            subtitle: "SSL/TLS Certificate Diagnostic Tool".to_string(),
            prompt: "Enter domain to check:".to_string(),
            hint: "Press Enter to continue, Esc to quit".to_string(),
        }
    }
}

/// Check status messages
#[derive(Debug, Clone, Deserialize)]
pub struct CheckMessages {
    pub dns_title: String,
    pub dns_resolving: String,
    pub dns_success: String,
    pub dns_failed: String,
    pub whois_title: String,
    pub whois_querying: String,
    pub tcp_title: String,
    pub tcp_connecting: String,
    pub tcp_success: String,
    pub tcp_failed: String,
    pub ssl_title: String,
    pub ssl_handshaking: String,
    pub ssl_success: String,
    pub ssl_failed: String,
    pub cert_title: String,
    pub cert_parsing: String,
    pub cert_valid: String,
    pub cert_expired: String,
    pub cert_expiring_soon: String,
}

impl Default for CheckMessages {
    fn default() -> Self {
        Self {
            dns_title: "DNS Resolution".to_string(),
            dns_resolving: "Resolving DNS records...".to_string(),
            dns_success: "DNS resolution successful".to_string(),
            dns_failed: "DNS resolution failed".to_string(),
            whois_title: "WHOIS Lookup".to_string(),
            whois_querying: "Querying WHOIS servers...".to_string(),
            tcp_title: "TCP Connectivity".to_string(),
            tcp_connecting: "Testing TCP connection...".to_string(),
            tcp_success: "TCP connection successful".to_string(),
            tcp_failed: "TCP connection failed".to_string(),
            ssl_title: "SSL/TLS Analysis".to_string(),
            ssl_handshaking: "Performing SSL handshake...".to_string(),
            ssl_success: "SSL handshake successful".to_string(),
            ssl_failed: "SSL handshake failed".to_string(),
            cert_title: "Certificate Analysis".to_string(),
            cert_parsing: "Parsing certificate...".to_string(),
            cert_valid: "Certificate is valid".to_string(),
            cert_expired: "Certificate has expired".to_string(),
            cert_expiring_soon: "Certificate expires within {days} days".to_string(),
        }
    }
}

/// Error messages
#[derive(Debug, Clone, Deserialize)]
pub struct ErrorMessages {
    pub invalid_domain: String,
    pub connection_refused: String,
    pub connection_timeout: String,
    pub handshake_failed: String,
    pub no_certificate: String,
    pub parse_error: String,
}

impl Default for ErrorMessages {
    fn default() -> Self {
        Self {
            invalid_domain: "Invalid domain name: {domain}".to_string(),
            connection_refused: "Connection refused to {ip}:{port}".to_string(),
            connection_timeout: "Connection timed out to {ip}:{port}".to_string(),
            handshake_failed: "SSL handshake failed: {error}".to_string(),
            no_certificate: "No certificate received from server".to_string(),
            parse_error: "Failed to parse certificate: {error}".to_string(),
        }
    }
}

/// Recommendation messages
#[derive(Debug, Clone, Deserialize)]
pub struct RecommendationMessages {
    pub upgrade_tls: String,
    pub disable_legacy: String,
    pub renew_soon: String,
    pub renew_urgent: String,
    pub fix_chain: String,
    pub use_strong_cipher: String,
}

impl Default for RecommendationMessages {
    fn default() -> Self {
        Self {
            upgrade_tls: "Consider upgrading to TLS 1.3 for improved security".to_string(),
            disable_legacy: "Disable legacy protocols (TLS 1.0, TLS 1.1, SSLv3)".to_string(),
            renew_soon: "Certificate expires in {days} days - plan renewal".to_string(),
            renew_urgent: "Certificate expires in {days} days - renew immediately".to_string(),
            fix_chain: "Fix certificate chain - missing intermediate certificates".to_string(),
            use_strong_cipher: "Consider using stronger cipher suites".to_string(),
        }
    }
}

/// Report messages
#[derive(Debug, Clone, Deserialize)]
pub struct ReportMessages {
    pub title: String,
    pub generated: String,
    pub summary: String,
    pub details: String,
    pub recommendations: String,
    pub export_pem: String,
    pub export_ical: String,
}

impl Default for ReportMessages {
    fn default() -> Self {
        Self {
            title: "SSL/TLS Diagnostic Report".to_string(),
            generated: "Generated on {date}".to_string(),
            summary: "Summary".to_string(),
            details: "Detailed Results".to_string(),
            recommendations: "Recommendations".to_string(),
            export_pem: "Export Certificate Chain (PEM)".to_string(),
            export_ical: "Export Expiry Reminder (iCal)".to_string(),
        }
    }
}

/// Navigation hints for each screen
#[derive(Debug, Clone, Deserialize)]
pub struct HintMessages {
    pub welcome: String,
    pub domain_input: String,
    pub dns_results: String,
    pub ip_selection: String,
    pub port_selection: String,
    pub running: String,
    pub results: String,
    pub save_prompt: String,
    pub error: String,
}

impl Default for HintMessages {
    fn default() -> Self {
        Self {
            welcome: "Enter: Start │ q: Quit │ ?: Help".to_string(),
            domain_input: "Enter: Submit │ Esc: Back │ ?: Help".to_string(),
            dns_results: "Enter: Continue │ Esc: Back │ ?: Help".to_string(),
            ip_selection: "↑/↓: Navigate │ Space: Toggle │ a: All │ Enter: Continue │ ?: Help"
                .to_string(),
            port_selection: "Enter: Submit │ Esc: Back │ ?: Help".to_string(),
            running: "Please wait...".to_string(),
            results: "↑/↓: Scroll │ e: Expand │ s: Save │ ?: Help │ q: Quit".to_string(),
            save_prompt: "Enter: Save │ Esc: Cancel".to_string(),
            error: "r: Retry │ q: Quit │ ?: Help".to_string(),
        }
    }
}

/// A single help section
#[derive(Debug, Clone, Default, Deserialize)]
pub struct HelpSection {
    pub header: String,
    pub content: String,
}

/// Help overlay messages
#[derive(Debug, Clone, Deserialize)]
pub struct HelpMessages {
    pub title: String,
    #[serde(default)]
    pub sections: Vec<HelpSection>,
}

impl Default for HelpMessages {
    fn default() -> Self {
        Self {
            title: "SSL Toolkit Help".to_string(),
            sections: vec![
                HelpSection {
                    header: "Navigation".to_string(),
                    content: "Use arrow keys or j/k to navigate up and down. Press Enter to confirm or continue.".to_string(),
                },
                HelpSection {
                    header: "Global Keys".to_string(),
                    content: "Press ? or F1 for help, Esc to go back, q to quit the application.".to_string(),
                },
                HelpSection {
                    header: "Results View".to_string(),
                    content: "Press e to expand/collapse sections, s to save the report, ↑/↓ to scroll.".to_string(),
                },
                HelpSection {
                    header: "IP Selection".to_string(),
                    content: "Press Space to toggle selection, a to select all, Tab for custom IP input.".to_string(),
                },
                HelpSection {
                    header: "Error Recovery".to_string(),
                    content: "Press r to retry the last operation, or q to quit.".to_string(),
                },
            ],
        }
    }
}

/// All messages
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Messages {
    #[serde(default)]
    pub header: HeaderMessages,
    #[serde(default)]
    pub footer: FooterMessages,
    #[serde(default)]
    pub welcome: WelcomeMessages,
    #[serde(default)]
    pub checks: CheckMessages,
    #[serde(default)]
    pub errors: ErrorMessages,
    #[serde(default)]
    pub recommendations: RecommendationMessages,
    #[serde(default)]
    pub report: ReportMessages,
    #[serde(default)]
    pub hints: HintMessages,
    #[serde(default)]
    pub help: HelpMessages,
}

impl Messages {
    /// Load messages from the default config file
    pub fn load_default() -> Result<Self, ConfigError> {
        let config_path = Path::new("config/messages.toml");
        if config_path.exists() {
            Self::load_from_file(config_path)
        } else {
            Ok(Self::default())
        }
    }

    /// Load messages from a specific file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path).map_err(|_| ConfigError::FileNotFound {
            path: path.display().to_string(),
        })?;

        toml::from_str(&content).map_err(|e| ConfigError::ParseError {
            message: e.to_string(),
        })
    }

    /// Format a message with placeholder substitution
    pub fn format(template: &str, vars: &HashMap<&str, String>) -> String {
        let mut result = template.to_string();
        for (key, value) in vars {
            result = result.replace(&format!("{{{}}}", key), value);
        }
        result
    }
}
