//! CT log search command implementation

use crate::cli::OutputFormat;
use crate::ct::{search_ct_logs, CtLogEntry};
use crate::error::Result;
use crate::output::{create_spinner, print_header, print_info, print_json};
use console::style;

/// Run the CT search command
pub async fn run_ct_search(
    domain: &str,
    include_expired: bool,
    limit: usize,
    issuer_filter: Option<&str>,
    format: OutputFormat,
) -> Result<()> {
    let spinner = create_spinner(&format!("Searching CT logs for {}...", domain));

    let result = search_ct_logs(domain, include_expired).await?;

    spinner.finish_and_clear();

    // Filter by issuer if specified
    let mut entries: Vec<&CtLogEntry> = result.entries.iter().collect();

    if let Some(issuer) = issuer_filter {
        entries.retain(|e| e.issuer_name.to_lowercase().contains(&issuer.to_lowercase()));
    }

    // Limit results
    if entries.len() > limit {
        entries.truncate(limit);
    }

    // Output
    match format {
        OutputFormat::Json => {
            print_json(&entries)?;
        }
        _ => {
            print_header(&format!("Certificate Transparency Results: {}", domain));

            print_info(&format!(
                "Found {} certificates (searched in {}ms)",
                result.total_entries, result.search_time_ms
            ));

            if entries.is_empty() {
                println!("\n  No certificates found matching criteria");
            } else {
                println!();

                for (i, entry) in entries.iter().enumerate() {
                    let expiry_style = if entry.not_after < chrono::Utc::now() {
                        style("expired").red().dim()
                    } else {
                        style("valid").green()
                    };

                    println!(
                        "  {} {} ({})",
                        style(format!("{}.", i + 1)).dim(),
                        style(&entry.common_name).bold(),
                        expiry_style
                    );
                    println!(
                        "     {} {}",
                        style("Issuer:").dim(),
                        truncate_string(&entry.issuer_name, 60)
                    );
                    println!(
                        "     {} {} to {}",
                        style("Validity:").dim(),
                        entry.not_before.format("%Y-%m-%d"),
                        entry.not_after.format("%Y-%m-%d")
                    );
                    if !entry.name_value.is_empty() && entry.name_value != entry.common_name {
                        println!(
                            "     {} {}",
                            style("SANs:").dim(),
                            truncate_string(&entry.name_value.replace('\n', ", "), 60)
                        );
                    }
                    println!();
                }

                if result.total_entries > limit {
                    print_info(&format!(
                        "Showing {} of {} results (use --limit to see more)",
                        limit, result.total_entries
                    ));
                }
            }
        }
    }

    Ok(())
}

fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len - 3])
    } else {
        s.to_string()
    }
}
