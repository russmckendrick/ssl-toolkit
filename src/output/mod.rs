//! Output formatting module
//!
//! Provides various output formats:
//! - Rich terminal output with colors and tables
//! - JSON export
//! - Markdown reports
//! - HTML reports

pub mod html;
pub mod json;
pub mod markdown;
pub mod terminal;

pub use html::{generate_html_report, write_html_file};
pub use json::{print_json, to_json_output, write_json_file, JsonOutput};
pub use markdown::{generate_markdown_report, print_markdown, write_markdown_file};
pub use terminal::{
    create_progress_bar, create_spinner, print_batch_summary, print_certificate_chain,
    print_certificate_info, print_dns_info, print_error, print_header, print_info,
    print_security_grade, print_success, print_warning,
};
