//! Render TestResult/DetailSection to terminal

use crate::models::{CheckStatus, DetailSection, TestResult};
use crate::output::cert_chain;
use crate::output::tables;
use console::style;

/// Print a full test result with all detail sections
pub fn print_test_result(result: &TestResult, verbose: bool) {
    // Status icon + title + summary
    let icon = status_icon(result.status);
    println!(
        "  {} {} {}",
        icon,
        style(&result.title).bold(),
        style(&result.summary).dim()
    );

    if !verbose {
        return;
    }

    // Detail sections
    for section in &result.details {
        print_detail_section(section);
    }

    // Test steps
    if !result.test_steps.is_empty() {
        println!();
        for step in &result.test_steps {
            let icon = status_icon(step.status);
            print!("    {} {}", icon, step.description);
            if let Some(details) = &step.details {
                print!(" {}", style(format!("({})", details)).dim());
            }
            println!();
        }
    }

    // Recommendations
    if !result.recommendations.is_empty() {
        println!();
        println!("    {}", style("Recommendations:").yellow().bold());
        for rec in &result.recommendations {
            println!("    {} {}", style("→").yellow(), rec);
        }
    }

    println!();
}

/// Print a compact status line (for non-verbose direct mode)
pub fn print_status_line(result: &TestResult) {
    let icon = status_icon(result.status);
    println!("  {} {}: {}", icon, result.title, result.summary);
}

fn print_detail_section(section: &DetailSection) {
    match section {
        DetailSection::KeyValue { title, pairs } => {
            if let Some(t) = title {
                println!();
                println!("    {}", style(t).bold());
            }
            let max_key_len = pairs.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
            for (key, value) in pairs {
                let dots = ".".repeat(max_key_len.saturating_sub(key.len()) + 2);
                println!("    {} {} {}", style(key).dim(), style(dots).dim(), value);
            }
        }
        DetailSection::Table {
            title,
            headers,
            rows,
        } => {
            if let Some(t) = title {
                println!();
                println!("    {}", style(t).bold());
            }
            tables::print_table(headers, rows);
        }
        DetailSection::List { title, items } => {
            if let Some(t) = title {
                println!();
                println!("    {}", style(t).bold());
            }
            for item in items {
                println!("    • {}", item);
            }
        }
        DetailSection::Text { title, content } => {
            if let Some(t) = title {
                println!();
                println!("    {}", style(t).bold());
            }
            for line in content.lines() {
                println!("      {}", line);
            }
        }
        DetailSection::CertificateChain { certificates } => {
            println!();
            println!("    {}", style("Certificate Chain").bold());
            cert_chain::print_cert_chain(certificates);
        }
    }
}

/// Format a full test result to a string (for paged output)
pub fn format_test_result(result: &TestResult, verbose: bool) -> String {
    let mut out = String::new();
    let icon = status_icon(result.status);
    out.push_str(&format!(
        "  {} {} {}\n",
        icon,
        style(&result.title).bold(),
        style(&result.summary).dim()
    ));

    if !verbose {
        return out;
    }

    for section in &result.details {
        out.push_str(&format_detail_section(section));
    }

    if !result.test_steps.is_empty() {
        out.push('\n');
        for step in &result.test_steps {
            let icon = status_icon(step.status);
            out.push_str(&format!("    {} {}", icon, step.description));
            if let Some(details) = &step.details {
                out.push_str(&format!(" {}", style(format!("({})", details)).dim()));
            }
            out.push('\n');
        }
    }

    if !result.recommendations.is_empty() {
        out.push('\n');
        out.push_str(&format!(
            "    {}\n",
            style("Recommendations:").yellow().bold()
        ));
        for rec in &result.recommendations {
            out.push_str(&format!("    {} {}\n", style("→").yellow(), rec));
        }
    }

    out.push('\n');
    out
}

fn format_detail_section(section: &DetailSection) -> String {
    let mut out = String::new();
    match section {
        DetailSection::KeyValue { title, pairs } => {
            if let Some(t) = title {
                out.push('\n');
                out.push_str(&format!("    {}\n", style(t).bold()));
            }
            let max_key_len = pairs.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
            for (key, value) in pairs {
                let dots = ".".repeat(max_key_len.saturating_sub(key.len()) + 2);
                out.push_str(&format!(
                    "    {} {} {}\n",
                    style(key).dim(),
                    style(dots).dim(),
                    value
                ));
            }
        }
        DetailSection::Table {
            title,
            headers,
            rows,
        } => {
            if let Some(t) = title {
                out.push('\n');
                out.push_str(&format!("    {}\n", style(t).bold()));
            }
            out.push_str(&tables::format_table(headers, rows));
        }
        DetailSection::List { title, items } => {
            if let Some(t) = title {
                out.push('\n');
                out.push_str(&format!("    {}\n", style(t).bold()));
            }
            for item in items {
                out.push_str(&format!("    • {}\n", item));
            }
        }
        DetailSection::Text { title, content } => {
            if let Some(t) = title {
                out.push('\n');
                out.push_str(&format!("    {}\n", style(t).bold()));
            }
            for line in content.lines() {
                out.push_str(&format!("      {}\n", line));
            }
        }
        DetailSection::CertificateChain { certificates } => {
            out.push('\n');
            out.push_str(&format!("    {}\n", style("Certificate Chain").bold()));
            out.push_str(&cert_chain::format_cert_chain(certificates));
        }
    }
    out
}

fn status_icon(status: CheckStatus) -> console::StyledObject<&'static str> {
    match status {
        CheckStatus::Pass => style("✓").green(),
        CheckStatus::Warning => style("⚠").yellow(),
        CheckStatus::Fail => style("✗").red(),
    }
}
