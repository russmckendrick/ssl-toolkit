//! Progress indicators for CLI mode
//!
//! This module provides progress display using indicatif and console.

use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

/// Progress tracker for check operations
pub struct ProgressTracker {
    bar: ProgressBar,
    current_check: u64,
}

impl ProgressTracker {
    /// Create a new progress tracker with the given total number of checks
    pub fn new(total_checks: u64) -> Self {
        let bar = ProgressBar::new(total_checks);
        bar.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} {msg}")
                .expect("Invalid progress template")
                .progress_chars("#>-"),
        );
        bar.enable_steady_tick(Duration::from_millis(100));

        Self {
            bar,
            current_check: 0,
        }
    }

    /// Update the current check being performed
    pub fn set_message(&self, message: &str) {
        self.bar.set_message(message.to_string());
    }

    /// Advance to the next check
    pub fn advance(&mut self, message: &str) {
        self.current_check += 1;
        self.bar.set_position(self.current_check);
        self.bar.set_message(message.to_string());
    }

    /// Mark a check as complete with a status message
    pub fn complete_check(&mut self, message: &str) {
        self.bar.println(message);
        self.bar.inc(1);
        self.current_check += 1;
    }

    /// Finish the progress bar
    pub fn finish(&self, message: &str) {
        self.bar.finish_with_message(message.to_string());
    }

    /// Finish and clear the progress bar
    pub fn finish_and_clear(&self) {
        self.bar.finish_and_clear();
    }
}

/// Create a simple spinner for indeterminate operations
pub fn create_spinner(message: &str) -> ProgressBar {
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .expect("Invalid spinner template"),
    );
    spinner.set_message(message.to_string());
    spinner.enable_steady_tick(Duration::from_millis(80));
    spinner
}

/// Print a status line with an icon
pub fn print_status(icon: &str, message: &str) {
    println!("{} {}", icon, message);
}

/// Print a pass status
pub fn print_pass(message: &str) {
    println!("  {} {}", style("✓").green(), message);
}

/// Print a fail status
pub fn print_fail(message: &str) {
    println!("  {} {}", style("✗").red(), message);
}

/// Print a warning status
pub fn print_warning(message: &str) {
    println!("  {} {}", style("⚠").yellow(), message);
}

/// Print an info status
pub fn print_info(message: &str) {
    println!("  {} {}", style("ℹ").cyan(), message);
}
