//! Interactive mode for ssl-toolkit
//!
//! Provides a full TUI dashboard using ratatui

use crate::error::Result;
use crate::tui::TuiRunner;

/// Interactive session using TUI
pub struct InteractiveSession;

impl Default for InteractiveSession {
    fn default() -> Self {
        Self::new()
    }
}

impl InteractiveSession {
    pub fn new() -> Self {
        Self
    }

    /// Run the interactive TUI session
    pub async fn run(&mut self) -> Result<()> {
        let mut runner = TuiRunner::new()?;
        runner.run().await
    }
}
