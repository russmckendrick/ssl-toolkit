//! Watch command implementation

use crate::certificate::get_certificate_chain;
use crate::error::Result;
use crate::output::{print_error, print_info, print_success, print_warning};
use chrono::Utc;
use console::style;
use std::time::Duration;
use tokio::time::sleep;

/// Run the watch command
pub async fn run_watch(
    domain: &str,
    interval_secs: u64,
    count: u64,
    alert_on_change: bool,
    alert_expiry_days: Option<i64>,
) -> Result<()> {
    let interval = Duration::from_secs(interval_secs);
    let mut iterations = 0u64;
    let mut last_fingerprint: Option<String> = None;
    let mut last_expiry_days: Option<i64> = None;

    println!(
        "\n{} Watching {} (interval: {}s, press Ctrl+C to stop)\n",
        style("👁").cyan(),
        style(domain).yellow().bold(),
        interval_secs
    );

    loop {
        iterations += 1;

        // Check if we've reached the count limit
        if count > 0 && iterations > count {
            print_info("Watch limit reached, stopping");
            break;
        }

        let check_time = Utc::now().format("%Y-%m-%d %H:%M:%S");

        match get_certificate_chain(domain, 443, None, Duration::from_secs(10)) {
            Ok((chain, _, _, response_time)) => {
                if let Some(cert) = chain.leaf() {
                    let fingerprint = cert.fingerprint_sha256.clone();
                    let expiry_days = cert.days_until_expiry;

                    // Check for certificate change
                    let changed = last_fingerprint
                        .as_ref()
                        .map(|f| f != &fingerprint)
                        .unwrap_or(false);

                    if changed && alert_on_change {
                        println!(
                            "{} {} Certificate changed! New fingerprint: {}",
                            style(format!("[{}]", check_time)).dim(),
                            style("⚠️ ALERT:").red().bold(),
                            &fingerprint[..16]
                        );
                    }

                    // Check expiry alert
                    if let Some(threshold) = alert_expiry_days {
                        if expiry_days <= threshold && expiry_days >= 0 {
                            println!(
                                "{} {} Certificate expires in {} days!",
                                style(format!("[{}]", check_time)).dim(),
                                style("⚠️ ALERT:").yellow().bold(),
                                expiry_days
                            );
                        }
                    }

                    // Normal status output
                    let expiry_style = if expiry_days < 0 {
                        style(format!("expired {} days ago", expiry_days.abs())).red()
                    } else if expiry_days <= 7 {
                        style(format!("{} days", expiry_days)).red().bold()
                    } else if expiry_days <= 30 {
                        style(format!("{} days", expiry_days)).yellow()
                    } else {
                        style(format!("{} days", expiry_days)).green()
                    };

                    let change_indicator = if changed {
                        style(" [CHANGED]").red().bold()
                    } else {
                        style("").dim()
                    };

                    println!(
                        "{} {} {} • Expiry: {} • Response: {}ms{}",
                        style(format!("[{}]", check_time)).dim(),
                        style("✓").green(),
                        domain,
                        expiry_style,
                        response_time,
                        change_indicator
                    );

                    last_fingerprint = Some(fingerprint);
                    last_expiry_days = Some(expiry_days);
                }
            }
            Err(e) => {
                println!(
                    "{} {} {} • Error: {}",
                    style(format!("[{}]", check_time)).dim(),
                    style("✗").red(),
                    domain,
                    style(e.to_string()).red()
                );
            }
        }

        // Wait for next interval
        sleep(interval).await;
    }

    Ok(())
}
