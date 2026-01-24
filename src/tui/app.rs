//! TUI Application state and event handling

use crate::certificate::{self, CertificateChain, SecurityGrade};
use crate::cli::args::OutputFormat;
use crate::dns::{self, DnsInfo};
use crate::error::{Result, SslToolkitError};
use crate::hpkp;
use crate::tui::events::{AppEvent, CheckData, CheckResult, EventHandler, KeyAction};
use crate::tui::widgets::{
    input::InputState,
    menu::{MenuItem, MenuState},
    results::{ResultsData, ResultsState},
    status::LoadingSpinner,
};
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io::{self, Stdout};
use std::time::Duration;
use tokio::sync::mpsc;

/// Application state
#[derive(Debug, Clone, PartialEq)]
pub enum AppState {
    /// Main menu
    MainMenu,
    /// Input dialog for domain
    InputDomain,
    /// Input dialog for port
    InputPort,
    /// Input dialog for file path (batch)
    InputFile,
    /// Input for second domain (compare)
    InputSecondDomain,
    /// Loading/checking state
    Checking,
    /// Display results
    Results,
    /// Settings menu
    Settings,
    /// Error display
    Error(String),
    /// Exiting
    Quit,
}

/// Main application struct
pub struct App {
    pub state: AppState,
    pub previous_state: Option<AppState>,

    // Menu state
    pub menu: MenuState,

    // Input state
    pub domain_input: InputState,
    pub port_input: InputState,
    pub file_input: InputState,
    pub second_domain_input: InputState,

    // Results state
    pub results: ResultsState,
    pub results_data: Option<ResultsData>,

    // Settings
    pub output_format: OutputFormat,
    pub verbose: bool,
    pub skip_dns: bool,
    pub skip_ct: bool,
    pub skip_ocsp: bool,
    pub settings_index: usize,

    // Loading state
    pub spinner: LoadingSpinner,
    pub loading_message: String,

    // Current operation context
    pub current_domain: String,
    pub current_port: u16,

    // Should quit
    pub should_quit: bool,
}

impl Default for App {
    fn default() -> Self {
        Self {
            state: AppState::MainMenu,
            previous_state: None,
            menu: MenuState::default(),
            domain_input: InputState::new("Enter domain to check")
                .with_placeholder("example.com"),
            port_input: InputState::new("Enter port")
                .with_default("443"),
            file_input: InputState::new("Enter path to domains file")
                .with_placeholder("/path/to/domains.txt"),
            second_domain_input: InputState::new("Enter second domain")
                .with_placeholder("example.org"),
            results: ResultsState::default(),
            results_data: None,
            output_format: OutputFormat::Table,
            verbose: false,
            skip_dns: false,
            skip_ct: false,
            skip_ocsp: false,
            settings_index: 0,
            spinner: LoadingSpinner::new("Loading..."),
            loading_message: String::new(),
            current_domain: String::new(),
            current_port: 443,
            should_quit: false,
        }
    }
}

impl App {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if app is in an input mode where text entry is expected
    pub fn is_input_mode(&self) -> bool {
        matches!(
            self.state,
            AppState::InputDomain
                | AppState::InputPort
                | AppState::InputFile
                | AppState::InputSecondDomain
        )
    }

    /// Handle keyboard input
    pub fn handle_key(&mut self, action: KeyAction, event_tx: &mpsc::UnboundedSender<AppEvent>) {
        match &self.state {
            AppState::MainMenu => self.handle_menu_key(action, event_tx),
            AppState::InputDomain => self.handle_input_key(action, &mut self.domain_input.clone(), event_tx),
            AppState::InputPort => self.handle_port_input_key(action, event_tx),
            AppState::InputFile => self.handle_file_input_key(action, event_tx),
            AppState::InputSecondDomain => self.handle_second_domain_key(action, event_tx),
            AppState::Checking => self.handle_loading_key(action),
            AppState::Results => self.handle_results_key(action),
            AppState::Settings => self.handle_settings_key(action),
            AppState::Error(_) => self.handle_error_key(action),
            AppState::Quit => {}
        }
    }

    fn handle_menu_key(&mut self, action: KeyAction, event_tx: &mpsc::UnboundedSender<AppEvent>) {
        match action {
            KeyAction::Quit => {
                self.should_quit = true;
                self.state = AppState::Quit;
            }
            KeyAction::Up => self.menu.previous(),
            KeyAction::Down => self.menu.next(),
            KeyAction::Enter => {
                if let Some(item) = self.menu.selected() {
                    self.handle_menu_selection(item, event_tx);
                }
            }
            _ => {}
        }
    }

    fn handle_menu_selection(&mut self, item: MenuItem, _event_tx: &mpsc::UnboundedSender<AppEvent>) {
        match item {
            MenuItem::CheckDomain => {
                self.domain_input = InputState::new("Enter domain to check")
                    .with_placeholder("example.com");
                self.state = AppState::InputDomain;
            }
            MenuItem::BatchCheck => {
                self.file_input = InputState::new("Enter path to domains file")
                    .with_placeholder("/path/to/domains.txt");
                self.state = AppState::InputFile;
            }
            MenuItem::WatchDomain => {
                self.domain_input = InputState::new("Enter domain to watch")
                    .with_placeholder("example.com");
                self.state = AppState::InputDomain;
            }
            MenuItem::CompareCertificates => {
                self.domain_input = InputState::new("Enter first domain")
                    .with_placeholder("example.com");
                self.state = AppState::InputDomain;
            }
            MenuItem::SearchCtLogs => {
                self.domain_input = InputState::new("Enter domain to search")
                    .with_placeholder("example.com");
                self.state = AppState::InputDomain;
            }
            MenuItem::GenerateTlsa => {
                self.domain_input = InputState::new("Enter domain for TLSA")
                    .with_placeholder("example.com");
                self.state = AppState::InputDomain;
            }
            MenuItem::Settings => {
                self.settings_index = 0;
                self.state = AppState::Settings;
            }
            MenuItem::Exit => {
                self.should_quit = true;
                self.state = AppState::Quit;
            }
        }
    }

    fn handle_input_key(&mut self, action: KeyAction, _input: &mut InputState, event_tx: &mpsc::UnboundedSender<AppEvent>) {
        match action {
            KeyAction::Back => {
                self.state = AppState::MainMenu;
            }
            KeyAction::Enter => {
                if !self.domain_input.is_empty() {
                    self.current_domain = self.domain_input.value.clone();

                    // Check what menu item was selected to determine next step
                    match self.menu.selected() {
                        Some(MenuItem::CheckDomain) | Some(MenuItem::GenerateTlsa) => {
                            self.port_input = InputState::new("Enter port").with_default("443");
                            self.state = AppState::InputPort;
                        }
                        Some(MenuItem::CompareCertificates) => {
                            self.second_domain_input = InputState::new("Enter second domain")
                                .with_placeholder("example.org");
                            self.state = AppState::InputSecondDomain;
                        }
                        Some(MenuItem::WatchDomain) | Some(MenuItem::SearchCtLogs) => {
                            // Start operation directly
                            self.start_check(event_tx);
                        }
                        _ => {
                            self.state = AppState::MainMenu;
                        }
                    }
                } else {
                    self.domain_input.set_error("Domain cannot be empty");
                }
            }
            KeyAction::Char(c) => self.domain_input.insert(c),
            KeyAction::Backspace => self.domain_input.delete_backward(),
            KeyAction::Delete => self.domain_input.delete_forward(),
            KeyAction::Left => self.domain_input.move_left(),
            KeyAction::Right => self.domain_input.move_right(),
            KeyAction::Home => self.domain_input.move_home(),
            KeyAction::End => self.domain_input.move_end(),
            _ => {}
        }
    }

    fn handle_port_input_key(&mut self, action: KeyAction, event_tx: &mpsc::UnboundedSender<AppEvent>) {
        match action {
            KeyAction::Back => {
                self.state = AppState::InputDomain;
            }
            KeyAction::Enter => {
                match self.port_input.value.parse::<u16>() {
                    Ok(port) if port > 0 => {
                        self.current_port = port;
                        self.start_check(event_tx);
                    }
                    _ => {
                        self.port_input.set_error("Invalid port number");
                    }
                }
            }
            KeyAction::Char(c) if c.is_ascii_digit() => self.port_input.insert(c),
            KeyAction::Backspace => self.port_input.delete_backward(),
            KeyAction::Delete => self.port_input.delete_forward(),
            KeyAction::Left => self.port_input.move_left(),
            KeyAction::Right => self.port_input.move_right(),
            KeyAction::Home => self.port_input.move_home(),
            KeyAction::End => self.port_input.move_end(),
            _ => {}
        }
    }

    fn handle_file_input_key(&mut self, action: KeyAction, _event_tx: &mpsc::UnboundedSender<AppEvent>) {
        match action {
            KeyAction::Back => {
                self.state = AppState::MainMenu;
            }
            KeyAction::Enter => {
                if !self.file_input.is_empty() {
                    // TODO: Start batch check
                    self.state = AppState::Error("Batch check not yet implemented in TUI".to_string());
                } else {
                    self.file_input.set_error("File path cannot be empty");
                }
            }
            KeyAction::Char(c) => self.file_input.insert(c),
            KeyAction::Backspace => self.file_input.delete_backward(),
            KeyAction::Delete => self.file_input.delete_forward(),
            KeyAction::Left => self.file_input.move_left(),
            KeyAction::Right => self.file_input.move_right(),
            KeyAction::Home => self.file_input.move_home(),
            KeyAction::End => self.file_input.move_end(),
            _ => {}
        }
    }

    fn handle_second_domain_key(&mut self, action: KeyAction, _event_tx: &mpsc::UnboundedSender<AppEvent>) {
        match action {
            KeyAction::Back => {
                self.state = AppState::InputDomain;
            }
            KeyAction::Enter => {
                if !self.second_domain_input.is_empty() {
                    // TODO: Start comparison
                    self.state = AppState::Error("Certificate comparison not yet implemented in TUI".to_string());
                } else {
                    self.second_domain_input.set_error("Domain cannot be empty");
                }
            }
            KeyAction::Char(c) => self.second_domain_input.insert(c),
            KeyAction::Backspace => self.second_domain_input.delete_backward(),
            KeyAction::Delete => self.second_domain_input.delete_forward(),
            KeyAction::Left => self.second_domain_input.move_left(),
            KeyAction::Right => self.second_domain_input.move_right(),
            KeyAction::Home => self.second_domain_input.move_home(),
            KeyAction::End => self.second_domain_input.move_end(),
            _ => {}
        }
    }

    fn handle_loading_key(&mut self, action: KeyAction) {
        if matches!(action, KeyAction::Back | KeyAction::Quit) {
            // Cancel operation and go back
            self.state = AppState::MainMenu;
        }
    }

    fn handle_results_key(&mut self, action: KeyAction) {
        use crate::tui::widgets::results::ResultsFocus;

        match action {
            KeyAction::Quit => {
                self.should_quit = true;
                self.state = AppState::Quit;
            }
            KeyAction::Back => {
                self.state = AppState::MainMenu;
            }
            // Left/Right switches focus between panels
            KeyAction::Left => {
                self.results.focus_left();
            }
            KeyAction::Right => {
                self.results.focus_right();
            }
            // Up/Down behavior depends on which panel is focused
            KeyAction::Up => {
                match self.results.focus {
                    ResultsFocus::Sections => {
                        // Navigate sections
                        self.results.previous_section();
                    }
                    ResultsFocus::Content => {
                        // Scroll content
                        self.results.scroll_up(1);
                    }
                }
            }
            KeyAction::Down => {
                match self.results.focus {
                    ResultsFocus::Sections => {
                        // Navigate sections
                        self.results.next_section();
                    }
                    ResultsFocus::Content => {
                        // Scroll content
                        self.results.scroll_down(1, self.results.content_height);
                    }
                }
            }
            KeyAction::PageUp => {
                self.results.scroll_up(10);
            }
            KeyAction::PageDown => {
                self.results.scroll_down(10, self.results.content_height);
            }
            // Tab still works as quick section navigation
            KeyAction::Tab => {
                self.results.next_section();
            }
            KeyAction::BackTab => {
                self.results.previous_section();
            }
            // Enter on sections panel moves focus to content
            KeyAction::Enter => {
                if self.results.focus == ResultsFocus::Sections {
                    self.results.focus_right();
                }
            }
            _ => {}
        }
    }

    fn handle_settings_key(&mut self, action: KeyAction) {
        const SETTINGS_COUNT: usize = 6;

        match action {
            KeyAction::Back => {
                self.state = AppState::MainMenu;
            }
            KeyAction::Up => {
                if self.settings_index > 0 {
                    self.settings_index -= 1;
                } else {
                    self.settings_index = SETTINGS_COUNT - 1;
                }
            }
            KeyAction::Down => {
                self.settings_index = (self.settings_index + 1) % SETTINGS_COUNT;
            }
            KeyAction::Enter => {
                match self.settings_index {
                    0 => {
                        // Cycle output format
                        self.output_format = match self.output_format {
                            OutputFormat::Table => OutputFormat::Json,
                            OutputFormat::Json => OutputFormat::Markdown,
                            OutputFormat::Markdown => OutputFormat::Html,
                            OutputFormat::Html => OutputFormat::Plain,
                            OutputFormat::Plain => OutputFormat::Table,
                        };
                    }
                    1 => self.verbose = !self.verbose,
                    2 => self.skip_dns = !self.skip_dns,
                    3 => self.skip_ct = !self.skip_ct,
                    4 => self.skip_ocsp = !self.skip_ocsp,
                    5 => self.state = AppState::MainMenu, // Back
                    _ => {}
                }
            }
            _ => {}
        }
    }

    fn handle_error_key(&mut self, action: KeyAction) {
        if matches!(action, KeyAction::Enter | KeyAction::Back) {
            self.state = AppState::MainMenu;
        }
    }

    fn start_check(&mut self, event_tx: &mpsc::UnboundedSender<AppEvent>) {
        self.loading_message = format!("Checking {}:{}...", self.current_domain, self.current_port);
        self.spinner = LoadingSpinner::new(&self.loading_message);
        self.state = AppState::Checking;

        // Spawn async check task
        let domain = self.current_domain.clone();
        let port = self.current_port;
        let skip_dns = self.skip_dns;
        let skip_ct = self.skip_ct;
        let skip_ocsp = self.skip_ocsp;
        let tx = event_tx.clone();

        tokio::spawn(async move {
            let result = perform_ssl_check(&domain, port, skip_dns, skip_ct, skip_ocsp).await;
            let _ = tx.send(AppEvent::CheckComplete(Box::new(result)));
        });
    }

    /// Handle check completion
    pub fn handle_check_complete(&mut self, result: CheckResult) {
        if result.success {
            if let Some(data) = result.data {
                let mut results_data = ResultsData::new(&result.domain, result.port);
                results_data.grade = data.grade;
                results_data.chain = data.chain;
                results_data.dns = data.dns;

                self.results_data = Some(results_data);
                self.results = ResultsState::default();
                self.state = AppState::Results;
            } else {
                self.state = AppState::Error("No data received".to_string());
            }
        } else {
            self.state = AppState::Error(result.error.unwrap_or_else(|| "Unknown error".to_string()));
        }
    }

    /// Tick for animations
    pub fn tick(&mut self) {
        if self.state == AppState::Checking {
            self.spinner.tick();
        }
    }
}

/// Perform SSL check operation
async fn perform_ssl_check(
    domain: &str,
    port: u16,
    skip_dns: bool,
    _skip_ct: bool,
    skip_ocsp: bool,
) -> CheckResult {
    let timeout = Duration::from_secs(10);

    // Get certificate chain
    let chain_result = certificate::get_certificate_chain(domain, port, None, timeout);

    let chain = match chain_result {
        Ok((chain, _, _, _)) => chain,
        Err(e) => {
            return CheckResult {
                domain: domain.to_string(),
                port,
                success: false,
                data: None,
                error: Some(e.to_string()),
            };
        }
    };

    // Get DNS info
    let dns = if !skip_dns {
        match dns::DnsResolver::new().await {
            Ok(resolver) => resolver.get_dns_info(domain).await.ok(),
            Err(_) => None,
        }
    } else {
        None
    };

    // Check HSTS
    let has_hsts = hpkp::check_hsts(domain, port)
        .await
        .map(|h| h.present)
        .unwrap_or(false);

    // Check CAA
    let has_caa = dns.as_ref().map(|d| !d.caa_records.is_empty()).unwrap_or(false);

    // Calculate grade
    let grade = certificate::calculate_security_grade(&chain, has_hsts, has_caa);

    CheckResult {
        domain: domain.to_string(),
        port,
        success: true,
        data: Some(CheckData {
            grade: Some(grade),
            chain: Some(chain),
            dns,
        }),
        error: None,
    }
}

/// TUI runner that manages terminal and event loop
pub struct TuiRunner {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    events: EventHandler,
    app: App,
}

impl TuiRunner {
    /// Create a new TUI runner
    pub fn new() -> Result<Self> {
        // Setup terminal
        enable_raw_mode().map_err(|e| SslToolkitError::Other(e.to_string()))?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)
            .map_err(|e| SslToolkitError::Other(e.to_string()))?;

        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend).map_err(|e| SslToolkitError::Other(e.to_string()))?;

        let events = EventHandler::new(Duration::from_millis(100));
        let app = App::new();

        Ok(Self {
            terminal,
            events,
            app,
        })
    }

    /// Run the TUI event loop
    pub async fn run(&mut self) -> Result<()> {
        let event_tx = self.events.sender();

        loop {
            // Draw UI
            self.terminal
                .draw(|f| crate::tui::ui::draw(f, &mut self.app))
                .map_err(|e| SslToolkitError::Other(e.to_string()))?;

            // Handle events
            if let Some(event) = self.events.next().await {
                match event {
                    AppEvent::Key(key) => {
                        // Use input mode for text entry states, navigation mode otherwise
                        let action = if self.app.is_input_mode() {
                            KeyAction::from_input(key)
                        } else {
                            KeyAction::from_navigation(key)
                        };
                        self.app.handle_key(action, &event_tx);
                    }
                    AppEvent::Tick => {
                        self.app.tick();
                    }
                    AppEvent::CheckComplete(result) => {
                        self.app.handle_check_complete(*result);
                    }
                    AppEvent::Error(msg) => {
                        self.app.state = AppState::Error(msg);
                    }
                    AppEvent::Resize(_, _) => {
                        // Terminal will handle resize automatically
                    }
                }
            }

            if self.app.should_quit {
                break;
            }
        }

        Ok(())
    }
}

impl Drop for TuiRunner {
    fn drop(&mut self) {
        // Restore terminal
        let _ = disable_raw_mode();
        let _ = execute!(
            self.terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        );
        let _ = self.terminal.show_cursor();
    }
}
