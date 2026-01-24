//! Event handling for TUI

use crate::export::ExportResult;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use std::time::Duration;
use tokio::sync::mpsc;

/// Application events
#[derive(Debug, Clone)]
pub enum AppEvent {
    /// Keyboard input
    Key(KeyEvent),
    /// Tick for animations/updates
    Tick,
    /// Async operation completed
    CheckComplete(Box<CheckResult>),
    /// Export operation completed
    ExportComplete(Vec<ExportResult>),
    /// Error occurred
    Error(String),
    /// Resize event
    Resize(u16, u16),
}

/// Result from an SSL check operation
#[derive(Debug, Clone)]
pub struct CheckResult {
    pub domain: String,
    pub port: u16,
    pub success: bool,
    pub data: Option<CheckData>,
    pub error: Option<String>,
}

/// Data from a successful check
#[derive(Debug, Clone)]
pub struct CheckData {
    pub grade: Option<crate::certificate::SecurityGrade>,
    pub chain: Option<crate::certificate::CertificateChain>,
    pub dns: Option<crate::dns::DnsInfo>,
}

/// Event handler that polls for keyboard events
pub struct EventHandler {
    rx: mpsc::UnboundedReceiver<AppEvent>,
    _tx: mpsc::UnboundedSender<AppEvent>,
}

impl EventHandler {
    /// Create a new event handler
    pub fn new(tick_rate: Duration) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let event_tx = tx.clone();

        // Spawn event polling task
        tokio::spawn(async move {
            loop {
                // Poll for events with timeout
                if event::poll(tick_rate).unwrap_or(false) {
                    if let Ok(evt) = event::read() {
                        let app_event = match evt {
                            Event::Key(key) => AppEvent::Key(key),
                            Event::Resize(w, h) => AppEvent::Resize(w, h),
                            _ => continue,
                        };
                        if event_tx.send(app_event).is_err() {
                            break;
                        }
                    }
                } else {
                    // Send tick event
                    if event_tx.send(AppEvent::Tick).is_err() {
                        break;
                    }
                }
            }
        });

        Self { rx, _tx: tx }
    }

    /// Get the next event
    pub async fn next(&mut self) -> Option<AppEvent> {
        self.rx.recv().await
    }

    /// Get sender for sending events from async tasks
    pub fn sender(&self) -> mpsc::UnboundedSender<AppEvent> {
        self._tx.clone()
    }
}

/// Key action abstraction
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KeyAction {
    Quit,
    Back,
    Up,
    Down,
    Left,
    Right,
    Enter,
    Tab,
    BackTab,
    Char(char),
    Backspace,
    Delete,
    Home,
    End,
    PageUp,
    PageDown,
    None,
}

impl KeyAction {
    /// Convert key event to action for navigation mode (menu, results, settings)
    /// Uses vim-style navigation keys (j/k/h/l)
    pub fn from_navigation(key: KeyEvent) -> Self {
        match key.code {
            KeyCode::Char('q') if key.modifiers.is_empty() => KeyAction::Quit,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => KeyAction::Quit,
            KeyCode::Esc => KeyAction::Back,
            KeyCode::Up | KeyCode::Char('k') => KeyAction::Up,
            KeyCode::Down | KeyCode::Char('j') => KeyAction::Down,
            KeyCode::Left | KeyCode::Char('h') => KeyAction::Left,
            KeyCode::Right | KeyCode::Char('l') => KeyAction::Right,
            KeyCode::Enter => KeyAction::Enter,
            KeyCode::Tab => KeyAction::Tab,
            KeyCode::BackTab => KeyAction::BackTab,
            KeyCode::Backspace => KeyAction::Backspace,
            KeyCode::Delete => KeyAction::Delete,
            KeyCode::Home => KeyAction::Home,
            KeyCode::End => KeyAction::End,
            KeyCode::PageUp => KeyAction::PageUp,
            KeyCode::PageDown => KeyAction::PageDown,
            KeyCode::Char(c) => KeyAction::Char(c),
            _ => KeyAction::None,
        }
    }

    /// Convert key event to action for input mode (text entry)
    /// All characters pass through, only arrow keys for cursor movement
    pub fn from_input(key: KeyEvent) -> Self {
        match key.code {
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => KeyAction::Quit,
            KeyCode::Esc => KeyAction::Back,
            KeyCode::Up => KeyAction::Up,
            KeyCode::Down => KeyAction::Down,
            KeyCode::Left => KeyAction::Left,
            KeyCode::Right => KeyAction::Right,
            KeyCode::Enter => KeyAction::Enter,
            KeyCode::Tab => KeyAction::Tab,
            KeyCode::BackTab => KeyAction::BackTab,
            KeyCode::Backspace => KeyAction::Backspace,
            KeyCode::Delete => KeyAction::Delete,
            KeyCode::Home => KeyAction::Home,
            KeyCode::End => KeyAction::End,
            KeyCode::PageUp => KeyAction::PageUp,
            KeyCode::PageDown => KeyAction::PageDown,
            KeyCode::Char(c) => KeyAction::Char(c),
            _ => KeyAction::None,
        }
    }
}

impl From<KeyEvent> for KeyAction {
    fn from(key: KeyEvent) -> Self {
        // Default to navigation mode for backwards compatibility
        Self::from_navigation(key)
    }
}
