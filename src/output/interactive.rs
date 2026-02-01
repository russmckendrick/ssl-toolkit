//! Interactive prompts using inquire

use crate::cli::CertFormat;
use inquire::autocompletion::{Autocomplete, Replacement};
use inquire::validator::Validation;
use inquire::{Confirm, CustomUserError, MultiSelect, Select, Text};
use std::io::ErrorKind;
use std::net::IpAddr;
use std::path::PathBuf;

/// File path autocompleter for interactive prompts.
///
/// Provides tab-completion for file paths by scanning the filesystem
/// based on current input.
#[derive(Clone, Default)]
struct FilePathCompleter {
    input: String,
    paths: Vec<String>,
    lcp: String,
}

impl FilePathCompleter {
    fn update_input(&mut self, input: &str) -> Result<(), CustomUserError> {
        if input == self.input {
            return Ok(());
        }

        self.input = input.to_owned();
        self.paths.clear();

        let input_path = std::path::PathBuf::from(input);

        let fallback_parent = input_path
            .parent()
            .map(|p| {
                if p.to_string_lossy().is_empty() {
                    std::path::PathBuf::from(".")
                } else {
                    p.to_owned()
                }
            })
            .unwrap_or_else(|| std::path::PathBuf::from("."));

        let scan_dir = if input.ends_with('/') {
            input_path
        } else {
            fallback_parent.clone()
        };

        let entries = match std::fs::read_dir(scan_dir) {
            Ok(read_dir) => Ok(read_dir),
            Err(err) if err.kind() == ErrorKind::NotFound => std::fs::read_dir(fallback_parent),
            Err(err) => Err(err),
        }?
        .collect::<Result<Vec<_>, _>>()?;

        let limit = 15;
        for entry in entries.iter().take(limit + self.paths.len()) {
            let path = entry.path();
            let path_str = if path.is_dir() {
                format!("{}/", path.to_string_lossy())
            } else {
                path.to_string_lossy().to_string()
            };

            if path_str.starts_with(&self.input) && path_str.len() != self.input.len() {
                self.paths.push(path_str);
                if self.paths.len() >= limit {
                    break;
                }
            }
        }

        self.lcp = self.longest_common_prefix();

        Ok(())
    }

    fn longest_common_prefix(&self) -> String {
        let mut ret = String::new();

        let mut sorted = self.paths.clone();
        sorted.sort();
        if sorted.is_empty() {
            return ret;
        }

        let mut first_word = sorted.first().unwrap().chars();
        let mut last_word = sorted.last().unwrap().chars();

        loop {
            match (first_word.next(), last_word.next()) {
                (Some(c1), Some(c2)) if c1 == c2 => {
                    ret.push(c1);
                }
                _ => return ret,
            }
        }
    }
}

impl Autocomplete for FilePathCompleter {
    fn get_suggestions(&mut self, input: &str) -> Result<Vec<String>, CustomUserError> {
        self.update_input(input)?;
        Ok(self.paths.clone())
    }

    fn get_completion(
        &mut self,
        input: &str,
        highlighted_suggestion: Option<String>,
    ) -> Result<Replacement, CustomUserError> {
        self.update_input(input)?;

        Ok(match highlighted_suggestion {
            Some(suggestion) => Replacement::Some(suggestion),
            None => {
                if self.lcp.is_empty() {
                    Replacement::None
                } else {
                    Replacement::Some(self.lcp.clone())
                }
            }
        })
    }
}

/// Result of DNS failure prompt
pub enum DnsFailureAction {
    /// User entered a manual IP address
    ManualIp(IpAddr),
    /// User wants to try a different domain
    Retry,
    /// User wants to quit
    Quit,
}

/// Prompt for a domain name
pub fn prompt_domain() -> anyhow::Result<String> {
    let domain = Text::new("Domain to check:")
        .with_validator(|input: &str| {
            let input = input.trim();
            if input.is_empty() {
                return Ok(Validation::Invalid("Domain cannot be empty".into()));
            }
            let cleaned = input
                .strip_prefix("https://")
                .or_else(|| input.strip_prefix("http://"))
                .unwrap_or(input)
                .strip_suffix('/')
                .unwrap_or(input);
            if cleaned.contains(' ') || !cleaned.contains('.') {
                return Ok(Validation::Invalid(
                    "Please enter a valid domain name (e.g., example.com)".into(),
                ));
            }
            Ok(Validation::Valid)
        })
        .prompt()?;

    // Normalize
    let domain = domain.trim();
    let domain = domain
        .strip_prefix("https://")
        .or_else(|| domain.strip_prefix("http://"))
        .unwrap_or(domain);
    let domain = domain.strip_suffix('/').unwrap_or(domain);
    Ok(domain.to_lowercase())
}

/// Prompt for port number
pub fn prompt_port(default: u16) -> anyhow::Result<u16> {
    let default_str = default.to_string();
    let port = Text::new("Port:")
        .with_default(&default_str)
        .with_validator(|input: &str| match input.trim().parse::<u16>() {
            Ok(p) if p > 0 => Ok(Validation::Valid),
            _ => Ok(Validation::Invalid(
                "Please enter a valid port number (1-65535)".into(),
            )),
        })
        .prompt()?;

    Ok(port.trim().parse().unwrap_or(default))
}

/// Prompt for IP selection from resolved addresses, with option to enter manually
pub fn prompt_ip_selection(ips: &[IpAddr]) -> anyhow::Result<Vec<IpAddr>> {
    // Build items list: resolved IPs + manual entry option
    let mut items: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
    items.push("Enter IP address manually".to_string());

    let defaults: Vec<usize> = vec![0];

    let selections = MultiSelect::new("Select IPs to check:", items)
        .with_default(&defaults)
        .raw_prompt()?;

    let selected_indices: Vec<usize> = selections.iter().map(|opt| opt.index).collect();
    let manual_index = ips.len();

    if selected_indices.contains(&manual_index) {
        // User selected manual entry
        let manual_ip = prompt_manual_ip()?;
        let mut selected: Vec<IpAddr> = selected_indices
            .iter()
            .filter(|&&i| i != manual_index)
            .map(|&i| ips[i])
            .collect();
        selected.push(manual_ip);
        Ok(selected)
    } else if selected_indices.is_empty() {
        // If nothing selected, use first IP
        Ok(vec![ips[0]])
    } else {
        Ok(selected_indices.iter().map(|&i| ips[i]).collect())
    }
}

/// Prompt for a manual IP address
fn prompt_manual_ip() -> anyhow::Result<IpAddr> {
    let ip_str = Text::new("IP address:")
        .with_validator(|input: &str| {
            input
                .trim()
                .parse::<IpAddr>()
                .map(|_| Validation::Valid)
                .or(Ok(Validation::Invalid(
                    "Please enter a valid IP address (e.g., 93.184.216.34)".into(),
                )))
        })
        .prompt()?;

    Ok(ip_str.trim().parse()?)
}

/// Prompt when DNS resolution fails - let user enter IP manually, retry, or quit
pub fn prompt_dns_failure(domain: &str) -> anyhow::Result<DnsFailureAction> {
    println!();
    let items = vec![
        "Enter an IP address manually".to_string(),
        "Try a different domain".to_string(),
        "Quit".to_string(),
    ];

    let prompt_msg = format!(
        "No IP addresses found for {}. What would you like to do?",
        domain
    );

    let selection = Select::new(&prompt_msg, items).raw_prompt()?;

    match selection.index {
        0 => {
            let ip = prompt_manual_ip()?;
            Ok(DnsFailureAction::ManualIp(ip))
        }
        1 => Ok(DnsFailureAction::Retry),
        _ => Ok(DnsFailureAction::Quit),
    }
}

/// Prompt to save HTML report
pub fn prompt_save_report(default_path: &str) -> anyhow::Result<Option<String>> {
    let save = Confirm::new("Save HTML report?")
        .with_default(false)
        .prompt()?;

    if save {
        let path = Text::new("Report path:")
            .with_default(default_path)
            .prompt()?;
        Ok(Some(path))
    } else {
        Ok(None)
    }
}

/// Prompt for the report save path (used when user presses 's' in pager)
pub fn prompt_report_path(default_path: &str) -> anyhow::Result<String> {
    let path = Text::new("Save report to:")
        .with_default(default_path)
        .prompt()?;
    Ok(path)
}

/// Main menu action choices
pub enum MainMenuAction {
    CheckDomain,
    CertInfo,
    CertVerify,
    CertConvert,
    Quit,
}

/// Post-operation action choices
pub enum PostOperationAction {
    MainMenu,
    Quit,
}

/// Certificate verify mode chosen interactively
pub enum CertVerifyMode {
    KeyMatch {
        cert: PathBuf,
        key: PathBuf,
    },
    ChainValidation {
        chain: PathBuf,
        hostname: Option<String>,
    },
}

/// Parameters gathered interactively for cert convert
pub struct CertConvertParams {
    pub input: PathBuf,
    pub target_format: CertFormat,
    pub output: Option<PathBuf>,
    pub key: Option<PathBuf>,
    pub password: Option<String>,
}

/// Show the main menu and return the user's choice
pub fn prompt_main_menu() -> anyhow::Result<MainMenuAction> {
    println!();
    let items = vec![
        "Check a domain".to_string(),
        "Inspect certificate file(s)".to_string(),
        "Verify certificate & key".to_string(),
        "Convert certificate format".to_string(),
        "Quit".to_string(),
    ];

    let selection = Select::new("What would you like to do?", items).raw_prompt()?;

    Ok(match selection.index {
        0 => MainMenuAction::CheckDomain,
        1 => MainMenuAction::CertInfo,
        2 => MainMenuAction::CertVerify,
        3 => MainMenuAction::CertConvert,
        _ => MainMenuAction::Quit,
    })
}

/// Show the post-operation menu
pub fn prompt_post_operation() -> anyhow::Result<PostOperationAction> {
    println!();
    let items = vec!["Run another check".to_string(), "Quit".to_string()];

    let selection = Select::new("What next?", items).raw_prompt()?;

    Ok(match selection.index {
        0 => PostOperationAction::MainMenu,
        _ => PostOperationAction::Quit,
    })
}

/// Prompt for a file path, validating the file exists
fn prompt_file_path(prompt: &str) -> anyhow::Result<PathBuf> {
    let path = Text::new(prompt)
        .with_autocomplete(FilePathCompleter::default())
        .with_validator(|input: &str| {
            let p = PathBuf::from(input.trim());
            if p.is_file() {
                Ok(Validation::Valid)
            } else {
                Ok(Validation::Invalid(
                    format!("File not found: {}", input.trim()).into(),
                ))
            }
        })
        .prompt()?;
    Ok(PathBuf::from(path.trim()))
}

/// Prompt for an optional file path (empty to skip)
fn prompt_optional_file_path(prompt: &str) -> anyhow::Result<Option<PathBuf>> {
    let path = Text::new(prompt)
        .with_autocomplete(FilePathCompleter::default())
        .with_default("")
        .prompt()?;

    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let p = PathBuf::from(trimmed);
    if !p.is_file() {
        anyhow::bail!("File not found: {}", trimmed);
    }
    Ok(Some(p))
}

/// Interactively prompt for cert info file(s)
pub fn prompt_cert_info_interactive() -> anyhow::Result<Vec<PathBuf>> {
    let mut files = vec![prompt_file_path("Certificate file:")?];

    loop {
        let more = Confirm::new("Add another file?")
            .with_default(false)
            .prompt()?;
        if !more {
            break;
        }
        files.push(prompt_file_path("Certificate file:")?);
    }

    Ok(files)
}

/// Interactively prompt for cert verify mode and files
pub fn prompt_cert_verify_interactive() -> anyhow::Result<CertVerifyMode> {
    let items = vec![
        "Check that a private key matches a certificate".to_string(),
        "Validate a certificate chain".to_string(),
    ];

    let selection = Select::new("Verification mode:", items).raw_prompt()?;

    match selection.index {
        0 => {
            let cert = prompt_file_path("Certificate file:")?;
            let key = prompt_file_path("Private key file:")?;
            Ok(CertVerifyMode::KeyMatch { cert, key })
        }
        _ => {
            let chain = prompt_file_path("Chain file (PEM with one or more certs):")?;
            let hostname = Text::new("Hostname to validate (leave empty to skip):")
                .with_default("")
                .prompt()?;
            let hostname = if hostname.trim().is_empty() {
                None
            } else {
                Some(hostname.trim().to_string())
            };
            Ok(CertVerifyMode::ChainValidation { chain, hostname })
        }
    }
}

/// Interactively prompt for cert convert parameters
pub fn prompt_cert_convert_interactive() -> anyhow::Result<CertConvertParams> {
    let input = prompt_file_path("Input certificate file:")?;

    let formats = vec![
        "PEM".to_string(),
        "DER".to_string(),
        "PKCS#12 (.p12)".to_string(),
    ];
    let selection = Select::new("Target format:", formats).raw_prompt()?;

    let target_format = match selection.index {
        0 => CertFormat::Pem,
        1 => CertFormat::Der,
        _ => CertFormat::P12,
    };

    let key = if matches!(target_format, CertFormat::P12) {
        Some(prompt_file_path(
            "Private key file (required for PKCS#12):",
        )?)
    } else {
        None
    };

    let password = if matches!(target_format, CertFormat::P12) {
        let pwd = Text::new("PKCS#12 password (leave empty for none):")
            .with_default("")
            .prompt()?;
        if pwd.trim().is_empty() {
            None
        } else {
            Some(pwd)
        }
    } else {
        None
    };

    let output = prompt_optional_file_path("Output file (leave empty for default):")?;

    Ok(CertConvertParams {
        input,
        target_format,
        output,
        key,
        password,
    })
}
