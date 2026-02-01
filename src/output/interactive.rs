//! Interactive prompts using dialoguer

use dialoguer::{Confirm, Input, MultiSelect, Select};
use std::net::IpAddr;

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
