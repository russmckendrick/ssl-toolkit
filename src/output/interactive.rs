//! Interactive prompts using dialoguer

use crate::cli::CertFormat;
use dialoguer::{Confirm, Input, MultiSelect, Select};
use std::net::IpAddr;
use std::path::PathBuf;

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
    let domain: String = Input::new()
        .with_prompt("Domain to check")
        .validate_with(|input: &String| -> Result<(), &str> {
            let input = input.trim();
            if input.is_empty() {
                return Err("Domain cannot be empty");
            }
            // Basic domain validation
            let cleaned = input
                .strip_prefix("https://")
                .or_else(|| input.strip_prefix("http://"))
                .unwrap_or(input)
                .strip_suffix('/')
                .unwrap_or(input);
            if cleaned.contains(' ') || !cleaned.contains('.') {
                return Err("Please enter a valid domain name (e.g., example.com)");
            }
            Ok(())
        })
        .interact_text()?;

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
    let port: String = Input::new()
        .with_prompt("Port")
        .default(default.to_string())
        .validate_with(|input: &String| -> Result<(), &str> {
            match input.trim().parse::<u16>() {
                Ok(p) if p > 0 => Ok(()),
                _ => Err("Please enter a valid port number (1-65535)"),
            }
        })
        .interact_text()?;

    Ok(port.trim().parse().unwrap_or(default))
}

/// Prompt for IP selection from resolved addresses, with option to enter manually
pub fn prompt_ip_selection(ips: &[IpAddr]) -> anyhow::Result<Vec<IpAddr>> {
    // Build items list: resolved IPs + manual entry option
    let mut items: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
    items.push("Enter IP address manually".to_string());

    let defaults: Vec<bool> = ips
        .iter()
        .enumerate()
        .map(|(i, _)| i == 0)
        .chain(std::iter::once(false))
        .collect();

    let selections = MultiSelect::new()
        .with_prompt("Select IPs to check")
        .items(&items)
        .defaults(&defaults)
        .interact()?;

    let manual_index = ips.len();

    if selections.contains(&manual_index) {
        // User selected manual entry
        let manual_ip = prompt_manual_ip()?;
        let mut selected: Vec<IpAddr> = selections
            .iter()
            .filter(|&&i| i != manual_index)
            .map(|&i| ips[i])
            .collect();
        selected.push(manual_ip);
        Ok(selected)
    } else if selections.is_empty() {
        // If nothing selected, use first IP
        Ok(vec![ips[0]])
    } else {
        Ok(selections.iter().map(|&i| ips[i]).collect())
    }
}

/// Prompt for a manual IP address
fn prompt_manual_ip() -> anyhow::Result<IpAddr> {
    let ip_str: String = Input::new()
        .with_prompt("IP address")
        .validate_with(|input: &String| -> Result<(), &str> {
            input
                .trim()
                .parse::<IpAddr>()
                .map(|_| ())
                .map_err(|_| "Please enter a valid IP address (e.g., 93.184.216.34)")
        })
        .interact_text()?;

    Ok(ip_str.trim().parse()?)
}

/// Prompt when DNS resolution fails - let user enter IP manually, retry, or quit
pub fn prompt_dns_failure(domain: &str) -> anyhow::Result<DnsFailureAction> {
    println!();
    let items = &[
        "Enter an IP address manually",
        "Try a different domain",
        "Quit",
    ];

    let selection = Select::new()
        .with_prompt(format!(
            "No IP addresses found for {}. What would you like to do?",
            domain
        ))
        .items(items)
        .default(0)
        .interact()?;

    match selection {
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
    let save = Confirm::new()
        .with_prompt("Save HTML report?")
        .default(false)
        .interact()?;

    if save {
        let path: String = Input::new()
            .with_prompt("Report path")
            .default(default_path.to_string())
            .interact_text()?;
        Ok(Some(path))
    } else {
        Ok(None)
    }
}

/// Prompt for the report save path (used when user presses 's' in pager)
pub fn prompt_report_path(default_path: &str) -> anyhow::Result<String> {
    let path: String = Input::new()
        .with_prompt("Save report to")
        .default(default_path.to_string())
        .interact_text()?;
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
    let items = &[
        "Check a domain",
        "Inspect certificate file(s)",
        "Verify certificate & key",
        "Convert certificate format",
        "Quit",
    ];

    let selection = Select::new()
        .with_prompt("What would you like to do?")
        .items(items)
        .default(0)
        .interact()?;

    Ok(match selection {
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
    let items = &["Run another check", "Quit"];

    let selection = Select::new()
        .with_prompt("What next?")
        .items(items)
        .default(0)
        .interact()?;

    Ok(match selection {
        0 => PostOperationAction::MainMenu,
        _ => PostOperationAction::Quit,
    })
}

/// Prompt for a file path, validating the file exists
fn prompt_file_path(prompt: &str) -> anyhow::Result<PathBuf> {
    let path: String = Input::new()
        .with_prompt(prompt)
        .validate_with(|input: &String| -> Result<(), String> {
            let p = PathBuf::from(input.trim());
            if p.is_file() {
                Ok(())
            } else {
                Err(format!("File not found: {}", input.trim()))
            }
        })
        .interact_text()?;
    Ok(PathBuf::from(path.trim()))
}

/// Prompt for an optional file path (empty to skip)
fn prompt_optional_file_path(prompt: &str) -> anyhow::Result<Option<PathBuf>> {
    let path: String = Input::new()
        .with_prompt(prompt)
        .default(String::new())
        .allow_empty(true)
        .interact_text()?;

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
    let mut files = vec![prompt_file_path("Certificate file")?];

    loop {
        let more = Confirm::new()
            .with_prompt("Add another file?")
            .default(false)
            .interact()?;
        if !more {
            break;
        }
        files.push(prompt_file_path("Certificate file")?);
    }

    Ok(files)
}

/// Interactively prompt for cert verify mode and files
pub fn prompt_cert_verify_interactive() -> anyhow::Result<CertVerifyMode> {
    let items = &[
        "Check that a private key matches a certificate",
        "Validate a certificate chain",
    ];

    let selection = Select::new()
        .with_prompt("Verification mode")
        .items(items)
        .default(0)
        .interact()?;

    match selection {
        0 => {
            let cert = prompt_file_path("Certificate file")?;
            let key = prompt_file_path("Private key file")?;
            Ok(CertVerifyMode::KeyMatch { cert, key })
        }
        _ => {
            let chain = prompt_file_path("Chain file (PEM with one or more certs)")?;
            let hostname: String = Input::new()
                .with_prompt("Hostname to validate (leave empty to skip)")
                .default(String::new())
                .allow_empty(true)
                .interact_text()?;
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
    let input = prompt_file_path("Input certificate file")?;

    let formats = &["PEM", "DER", "PKCS#12 (.p12)"];
    let selection = Select::new()
        .with_prompt("Target format")
        .items(formats)
        .default(0)
        .interact()?;

    let target_format = match selection {
        0 => CertFormat::Pem,
        1 => CertFormat::Der,
        _ => CertFormat::P12,
    };

    let key = if matches!(target_format, CertFormat::P12) {
        Some(prompt_file_path("Private key file (required for PKCS#12)")?)
    } else {
        None
    };

    let password = if matches!(target_format, CertFormat::P12) {
        let pwd: String = Input::new()
            .with_prompt("PKCS#12 password (leave empty for none)")
            .default(String::new())
            .allow_empty(true)
            .interact_text()?;
        if pwd.trim().is_empty() {
            None
        } else {
            Some(pwd)
        }
    } else {
        None
    };

    let output = prompt_optional_file_path("Output file (leave empty for default)")?;

    Ok(CertConvertParams {
        input,
        target_format,
        output,
        key,
        password,
    })
}
