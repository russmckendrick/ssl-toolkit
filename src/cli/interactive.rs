//! Interactive mode for ssl-toolkit

use crate::cli::args::OutputFormat;
use crate::error::Result;
use console::style;
use dialoguer::{theme::ColorfulTheme, Input, Select};

/// Main menu options
#[derive(Debug, Clone, Copy)]
pub enum MainMenuOption {
    CheckDomain,
    BatchCheck,
    WatchDomain,
    CompareCertificates,
    SearchCtLogs,
    GenerateTlsa,
    Settings,
    Exit,
}

impl std::fmt::Display for MainMenuOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MainMenuOption::CheckDomain => write!(f, "Check SSL certificate for a domain"),
            MainMenuOption::BatchCheck => write!(f, "Batch check multiple domains"),
            MainMenuOption::WatchDomain => write!(f, "Watch a domain for certificate changes"),
            MainMenuOption::CompareCertificates => write!(f, "Compare two certificates"),
            MainMenuOption::SearchCtLogs => write!(f, "Search Certificate Transparency logs"),
            MainMenuOption::GenerateTlsa => write!(f, "Generate TLSA/DANE record"),
            MainMenuOption::Settings => write!(f, "Settings"),
            MainMenuOption::Exit => write!(f, "Exit"),
        }
    }
}

/// Interactive session state
pub struct InteractiveSession {
    pub theme: ColorfulTheme,
    pub output_format: OutputFormat,
    pub verbose: bool,
    pub skip_dns: bool,
    pub skip_ct: bool,
    pub skip_ocsp: bool,
}

impl Default for InteractiveSession {
    fn default() -> Self {
        InteractiveSession {
            theme: ColorfulTheme::default(),
            output_format: OutputFormat::Table,
            verbose: false,
            skip_dns: false,
            skip_ct: false,
            skip_ocsp: false,
        }
    }
}

impl InteractiveSession {
    pub fn new() -> Self {
        Self::default()
    }

    /// Run the interactive session
    pub async fn run(&mut self) -> Result<()> {
        self.print_welcome();

        loop {
            match self.show_main_menu()? {
                MainMenuOption::CheckDomain => {
                    if let Err(e) = self.check_domain().await {
                        eprintln!("{} {}", style("Error:").red().bold(), e);
                    }
                }
                MainMenuOption::BatchCheck => {
                    if let Err(e) = self.batch_check().await {
                        eprintln!("{} {}", style("Error:").red().bold(), e);
                    }
                }
                MainMenuOption::WatchDomain => {
                    if let Err(e) = self.watch_domain().await {
                        eprintln!("{} {}", style("Error:").red().bold(), e);
                    }
                }
                MainMenuOption::CompareCertificates => {
                    if let Err(e) = self.compare_certificates().await {
                        eprintln!("{} {}", style("Error:").red().bold(), e);
                    }
                }
                MainMenuOption::SearchCtLogs => {
                    if let Err(e) = self.search_ct_logs().await {
                        eprintln!("{} {}", style("Error:").red().bold(), e);
                    }
                }
                MainMenuOption::GenerateTlsa => {
                    if let Err(e) = self.generate_tlsa().await {
                        eprintln!("{} {}", style("Error:").red().bold(), e);
                    }
                }
                MainMenuOption::Settings => {
                    self.show_settings()?;
                }
                MainMenuOption::Exit => {
                    println!("\n{}", style("Goodbye!").cyan());
                    break;
                }
            }
            println!();
        }

        Ok(())
    }

    fn print_welcome(&self) {
        println!();
        println!(
            "{}",
            style("╔═══════════════════════════════════════╗").cyan()
        );
        println!(
            "{}",
            style("║         SSL Toolkit v0.1.0            ║").cyan()
        );
        println!(
            "{}",
            style("║   SSL/TLS Certificate Analysis Tool   ║").cyan()
        );
        println!(
            "{}",
            style("╚═══════════════════════════════════════╝").cyan()
        );
        println!();
    }

    fn show_main_menu(&self) -> Result<MainMenuOption> {
        let options = vec![
            MainMenuOption::CheckDomain,
            MainMenuOption::BatchCheck,
            MainMenuOption::WatchDomain,
            MainMenuOption::CompareCertificates,
            MainMenuOption::SearchCtLogs,
            MainMenuOption::GenerateTlsa,
            MainMenuOption::Settings,
            MainMenuOption::Exit,
        ];

        let selection = Select::with_theme(&self.theme)
            .with_prompt("What would you like to do?")
            .items(&options)
            .default(0)
            .interact()
            .map_err(|e| crate::error::SslToolkitError::Other(e.to_string()))?;

        Ok(options[selection])
    }

    async fn check_domain(&self) -> Result<()> {
        let domain: String = Input::with_theme(&self.theme)
            .with_prompt("Enter domain to check")
            .interact_text()
            .map_err(|e| crate::error::SslToolkitError::Other(e.to_string()))?;

        let port: u16 = Input::with_theme(&self.theme)
            .with_prompt("Port")
            .default(443)
            .interact_text()
            .map_err(|e| crate::error::SslToolkitError::Other(e.to_string()))?;

        println!(
            "\n{} Checking {}:{}...\n",
            style("→").cyan(),
            style(&domain).yellow(),
            port
        );

        // This would call the actual check functionality
        // For now, we'll just show a placeholder
        crate::commands::check::run_check(
            &domain,
            port,
            None,
            std::time::Duration::from_secs(10),
            self.skip_dns,
            self.skip_ct,
            self.skip_ocsp,
            self.output_format,
            self.verbose,
        )
        .await
    }

    async fn batch_check(&self) -> Result<()> {
        let file: String = Input::with_theme(&self.theme)
            .with_prompt("Enter path to domains file")
            .interact_text()
            .map_err(|e| crate::error::SslToolkitError::Other(e.to_string()))?;

        let parallel: usize = Input::with_theme(&self.theme)
            .with_prompt("Number of parallel checks")
            .default(5)
            .interact_text()
            .map_err(|e| crate::error::SslToolkitError::Other(e.to_string()))?;

        println!(
            "\n{} Running batch check on {}...\n",
            style("→").cyan(),
            style(&file).yellow()
        );

        crate::commands::batch::run_batch(
            &std::path::PathBuf::from(file),
            parallel,
            std::time::Duration::from_secs(10),
            self.skip_dns,
            self.skip_ct,
            self.skip_ocsp,
            false,
            self.output_format,
        )
        .await
    }

    async fn watch_domain(&self) -> Result<()> {
        let domain: String = Input::with_theme(&self.theme)
            .with_prompt("Enter domain to watch")
            .interact_text()
            .map_err(|e| crate::error::SslToolkitError::Other(e.to_string()))?;

        let interval: u64 = Input::with_theme(&self.theme)
            .with_prompt("Check interval (seconds)")
            .default(300)
            .interact_text()
            .map_err(|e| crate::error::SslToolkitError::Other(e.to_string()))?;

        println!(
            "\n{} Watching {} (interval: {}s)...\n",
            style("→").cyan(),
            style(&domain).yellow(),
            interval
        );
        println!("{}", style("Press Ctrl+C to stop").dim());

        crate::commands::watch::run_watch(&domain, interval, 0, false, None).await
    }

    async fn compare_certificates(&self) -> Result<()> {
        let first: String = Input::with_theme(&self.theme)
            .with_prompt("Enter first domain")
            .interact_text()
            .map_err(|e| crate::error::SslToolkitError::Other(e.to_string()))?;

        let second: String = Input::with_theme(&self.theme)
            .with_prompt("Enter second domain")
            .interact_text()
            .map_err(|e| crate::error::SslToolkitError::Other(e.to_string()))?;

        println!(
            "\n{} Comparing {} and {}...\n",
            style("→").cyan(),
            style(&first).yellow(),
            style(&second).yellow()
        );

        crate::commands::diff::run_diff(&first, Some(&second), None, 443, self.output_format).await
    }

    async fn search_ct_logs(&self) -> Result<()> {
        let domain: String = Input::with_theme(&self.theme)
            .with_prompt("Enter domain to search")
            .interact_text()
            .map_err(|e| crate::error::SslToolkitError::Other(e.to_string()))?;

        let include_expired = Select::with_theme(&self.theme)
            .with_prompt("Include expired certificates?")
            .items(&["No", "Yes"])
            .default(0)
            .interact()
            .map_err(|e| crate::error::SslToolkitError::Other(e.to_string()))?
            == 1;

        println!(
            "\n{} Searching CT logs for {}...\n",
            style("→").cyan(),
            style(&domain).yellow()
        );

        crate::commands::ct_search::run_ct_search(&domain, include_expired, 100, None, self.output_format).await
    }

    async fn generate_tlsa(&self) -> Result<()> {
        let domain: String = Input::with_theme(&self.theme)
            .with_prompt("Enter domain")
            .interact_text()
            .map_err(|e| crate::error::SslToolkitError::Other(e.to_string()))?;

        let port: u16 = Input::with_theme(&self.theme)
            .with_prompt("Port")
            .default(443)
            .interact_text()
            .map_err(|e| crate::error::SslToolkitError::Other(e.to_string()))?;

        println!(
            "\n{} Generating TLSA record for {}:{}...\n",
            style("→").cyan(),
            style(&domain).yellow(),
            port
        );

        crate::commands::tlsa::run_tlsa(&domain, port, 3, 1, 1, self.output_format).await
    }

    fn show_settings(&mut self) -> Result<()> {
        let options = vec![
            "Output format",
            "Verbose mode",
            "Skip DNS lookups",
            "Skip CT log checks",
            "Skip OCSP checks",
            "Back to main menu",
        ];

        loop {
            println!("\n{}", style("Current settings:").bold());
            println!("  Output format: {}", self.output_format);
            println!("  Verbose: {}", self.verbose);
            println!("  Skip DNS: {}", self.skip_dns);
            println!("  Skip CT: {}", self.skip_ct);
            println!("  Skip OCSP: {}", self.skip_ocsp);
            println!();

            let selection = Select::with_theme(&self.theme)
                .with_prompt("Change setting")
                .items(&options)
                .default(0)
                .interact()
                .map_err(|e| crate::error::SslToolkitError::Other(e.to_string()))?;

            match selection {
                0 => {
                    let formats = vec!["Table", "JSON", "Markdown", "HTML", "Plain"];
                    let format_selection = Select::with_theme(&self.theme)
                        .with_prompt("Select output format")
                        .items(&formats)
                        .default(0)
                        .interact()
                        .map_err(|e| crate::error::SslToolkitError::Other(e.to_string()))?;
                    self.output_format = match format_selection {
                        0 => OutputFormat::Table,
                        1 => OutputFormat::Json,
                        2 => OutputFormat::Markdown,
                        3 => OutputFormat::Html,
                        4 => OutputFormat::Plain,
                        _ => OutputFormat::Table,
                    };
                }
                1 => self.verbose = !self.verbose,
                2 => self.skip_dns = !self.skip_dns,
                3 => self.skip_ct = !self.skip_ct,
                4 => self.skip_ocsp = !self.skip_ocsp,
                5 => break,
                _ => {}
            }
        }

        Ok(())
    }
}
