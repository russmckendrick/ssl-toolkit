//! Interactive prompts using inquire

use crate::cli::CertFormat;
use inquire::autocompletion::{Autocomplete, Replacement};
use inquire::ui::{Attributes, Color, RenderConfig, StyleSheet, Styled};
use inquire::validator::Validation;
use inquire::{Confirm, CustomUserError, InquireError, MultiSelect, Select, Text};
use std::io::ErrorKind;
use std::net::IpAddr;
use std::path::PathBuf;

/// Initialize the global inquire theme with Tokyo Night Storm colors.
/// Call once at startup before any prompts.
pub fn init_theme() {
    inquire::set_global_render_config(tokyo_night_render_config());
}

/// Returns true if the error represents a user cancellation (Ctrl+C / Esc).
pub fn is_user_cancel(err: &anyhow::Error) -> bool {
    err.downcast_ref::<InquireError>()
        .map(|e| {
            matches!(
                e,
                InquireError::OperationCanceled | InquireError::OperationInterrupted
            )
        })
        .unwrap_or(false)
}

/// Build a `RenderConfig` using the Tokyo Night Storm palette.
fn tokyo_night_render_config() -> RenderConfig<'static> {
    // Tokyo Night Storm palette
    let primary = Color::rgb(122, 162, 247); // #7aa2f7
    let green = Color::rgb(158, 206, 106); // #9ece6a
    let foreground = Color::rgb(192, 202, 245); // #c0caf5
    let muted = Color::rgb(86, 95, 137); // #565f89
    let purple = Color::rgb(187, 154, 247); // #bb9af7
    let secondary = Color::rgb(169, 177, 214); // #a9b1d6
    let red = Color::rgb(247, 118, 142); // #f7768e

    let mut config = RenderConfig::empty();

    // Prompt prefix: ❯ in primary blue
    config.prompt_prefix = Styled::new("❯").with_fg(primary);
    // Answered prefix: ✓ in green
    config.answered_prompt_prefix = Styled::new("✓").with_fg(green);
    // Prompt text: bold foreground
    config.prompt = StyleSheet::new()
        .with_fg(foreground)
        .with_attr(Attributes::BOLD);
    // User answer: green
    config.answer = StyleSheet::new().with_fg(green);
    // Default value hint: muted
    config.default_value = StyleSheet::new().with_fg(muted);
    // Help message: muted
    config.help_message = StyleSheet::new().with_fg(muted);
    // Text input: foreground
    config.text_input = StyleSheet::new().with_fg(foreground);
    // Placeholder text: muted
    config.placeholder = StyleSheet::new().with_fg(muted);
    // Highlighted option prefix: ❯ in purple
    config.highlighted_option_prefix = Styled::new("❯").with_fg(purple);
    // Selected/highlighted option: purple
    config.selected_option = Some(StyleSheet::new().with_fg(purple));
    // Regular option: secondary
    config.option = StyleSheet::new().with_fg(secondary);
    // Selected checkbox: ✓ in green
    config.selected_checkbox = Styled::new("✓").with_fg(green);
    // Unselected checkbox: ○ muted
    config.unselected_checkbox = Styled::new("○").with_fg(muted);
    // Error message: ✗ prefix in red, message in red
    config.error_message = config
        .error_message
        .with_prefix(Styled::new("✗").with_fg(red))
        .with_message(StyleSheet::new().with_fg(red));
    // Canceled indicator: muted
    config.canceled_prompt_indicator = Styled::new("canceled").with_fg(muted);
    // Scroll indicators: muted
    config.scroll_up_prefix = Styled::new("▲").with_fg(muted);
    config.scroll_down_prefix = Styled::new("▼").with_fg(muted);

    config
}

/// File path autocompleter for interactive prompts.
///
/// Provides tab-completion for file paths by scanning the filesystem.
/// Directories are listed first (with trailing `/`), then files, both
/// sorted alphabetically. Hidden entries (starting with `.`) are only
/// shown when the user explicitly types a leading `.`.
#[derive(Clone, Default)]
struct FilePathCompleter {
    input: String,
    paths: Vec<String>,
    lcp: String,
}

impl FilePathCompleter {
    /// Check whether `c` is a path separator on the current platform.
    fn is_separator(c: char) -> bool {
        c == '/' || c == std::path::MAIN_SEPARATOR
    }

    fn update_input(&mut self, input: &str) -> Result<(), CustomUserError> {
        if input == self.input {
            return Ok(());
        }

        self.input = input.to_owned();
        self.paths.clear();

        let sep = std::path::MAIN_SEPARATOR;
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

        let ends_with_sep = input.ends_with(|c: char| Self::is_separator(c));
        let scan_dir = if ends_with_sep {
            input_path.clone()
        } else {
            fallback_parent.clone()
        };

        let entries = match std::fs::read_dir(&scan_dir) {
            Ok(read_dir) => Ok(read_dir),
            Err(err) if err.kind() == ErrorKind::NotFound => std::fs::read_dir(&fallback_parent),
            Err(err) => Err(err),
        }?
        .collect::<Result<Vec<_>, _>>()?;

        // Determine whether the user is typing a hidden-file prefix so we
        // know whether to include dotfiles in suggestions.
        let filename_prefix = if ends_with_sep {
            ""
        } else {
            input_path
                .file_name()
                .map(|f| f.to_str().unwrap_or(""))
                .unwrap_or("")
        };
        let show_hidden = filename_prefix.starts_with('.');

        // Prefix used when scanning the cwd (".") — we strip this from
        // display strings so suggestions look clean.
        let cwd_prefix_unix = format!(".{}", '/');
        let cwd_prefix_native = format!(".{}", sep);

        // Collect matching entries, split into dirs and files for sorting.
        let mut dirs: Vec<String> = Vec::new();
        let mut files: Vec<String> = Vec::new();

        for entry in &entries {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            // Skip hidden entries unless the user typed a dot prefix.
            if !show_hidden && name_str.starts_with('.') {
                continue;
            }

            let path = entry.path();

            // Build a clean display path, appending the platform separator
            // for directories. Strip the leading "./" or ".\" that comes
            // from scanning PathBuf::from(".").
            let display = if path.is_dir() {
                format!("{}{}", path.to_string_lossy(), sep)
            } else {
                path.to_string_lossy().to_string()
            };
            let display = display
                .strip_prefix(&cwd_prefix_unix)
                .or_else(|| display.strip_prefix(&cwd_prefix_native))
                .unwrap_or(&display)
                .to_string();

            // Only include entries that match what the user has typed so far.
            if !display.starts_with(&self.input) || display.len() == self.input.len() {
                continue;
            }

            if path.is_dir() {
                dirs.push(display);
            } else {
                files.push(display);
            }
        }

        // Sort each group alphabetically, then combine dirs-first.
        dirs.sort();
        files.sort();

        let limit = 15;
        for item in dirs.into_iter().chain(files) {
            self.paths.push(item);
            if self.paths.len() >= limit {
                break;
            }
        }

        self.lcp = self.longest_common_prefix();

        Ok(())
    }

    fn longest_common_prefix(&self) -> String {
        let mut ret = String::new();

        if self.paths.is_empty() {
            return ret;
        }

        let mut sorted = self.paths.clone();
        sorted.sort();

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
                // Only auto-complete to LCP when the user has typed something;
                // pressing Tab on an empty input shouldn't jump to a random prefix.
                if self.lcp.is_empty() || self.input.is_empty() {
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

/// Prompt for the report save path (used when user presses 's' in pager).
///
/// Shows the file explorer with autocomplete, starting from the current
/// working directory. The `default_filename` is appended to the cwd as
/// the initial value so the user can accept it or navigate elsewhere.
/// Returns `None` if the user cancels (Esc / Ctrl+C).
pub fn prompt_report_path(default_filename: &str) -> anyhow::Result<Option<String>> {
    let cwd = std::env::current_dir()
        .map(|p| {
            let s = p.to_string_lossy().to_string();
            let sep = std::path::MAIN_SEPARATOR;
            if s.ends_with(sep) {
                s
            } else {
                format!("{}{}", s, sep)
            }
        })
        .unwrap_or_default();

    let initial = format!("{}{}", cwd, default_filename);

    let result = Text::new("Save report to:")
        .with_initial_value(&initial)
        .with_autocomplete(FilePathCompleter::default())
        .with_help_message("Tab to autocomplete · Esc to cancel")
        .prompt();

    match result {
        Ok(path) => {
            let trimmed = path.trim();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                Ok(Some(trimmed.to_string()))
            }
        }
        Err(InquireError::OperationCanceled | InquireError::OperationInterrupted) => Ok(None),
        Err(e) => Err(e.into()),
    }
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

/// Return the user's home directory with a trailing path separator.
/// Falls back to an empty string if the home directory cannot be determined.
fn home_dir_prefix() -> String {
    let sep = std::path::MAIN_SEPARATOR;
    // Use dirs-style lookup: HOME on Unix, USERPROFILE on Windows.
    #[cfg(not(target_os = "windows"))]
    let home = std::env::var("HOME");
    #[cfg(target_os = "windows")]
    let home = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME"));

    home.map(|h| {
        if h.ends_with(sep) {
            h
        } else {
            format!("{}{}", h, sep)
        }
    })
    .unwrap_or_default()
}

/// Prompt for a file path, validating the file exists
fn prompt_file_path(prompt: &str) -> anyhow::Result<PathBuf> {
    let start = home_dir_prefix();
    let path = Text::new(prompt)
        .with_initial_value(&start)
        .with_autocomplete(FilePathCompleter::default())
        .with_help_message("Tab to autocomplete · Esc to cancel")
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
    let start = home_dir_prefix();
    let path = Text::new(prompt)
        .with_initial_value(&start)
        .with_autocomplete(FilePathCompleter::default())
        .with_help_message("Tab to autocomplete · Esc to cancel")
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
