//! Styled startup banner

use console::style;

/// Clear the terminal screen and move the cursor to the top-left.
pub fn clear_screen() {
    // ANSI escape: clear entire screen + move cursor to 1,1.
    // Works on macOS, Linux, and Windows 10+ terminals.
    print!("\x1B[2J\x1B[1;1H");
}

/// Display the ASCII art banner (only in interactive mode)
pub fn print_banner() {
    let banner = include_str!("../../templates/banner.txt");
    for line in banner.lines() {
        println!("{}", style(line).magenta().bold());
    }
    println!("  {}", style("SSL/TLS Certificate Diagnostic Tool").dim());
    println!();
}

/// Clear the screen and redraw the banner — used when returning to the
/// main menu or starting a new check.
pub fn refresh_banner() {
    clear_screen();
    print_banner();
}
