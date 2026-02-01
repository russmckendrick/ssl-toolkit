//! Styled startup banner

use console::style;

/// Display the ASCII art banner (only in interactive mode)
pub fn print_banner() {
    let banner = include_str!("../../templates/banner.txt");
    for line in banner.lines() {
        println!("{}", style(line).magenta().bold());
    }
    println!("  {}", style("SSL/TLS Certificate Diagnostic Tool").dim());
    println!();
}
