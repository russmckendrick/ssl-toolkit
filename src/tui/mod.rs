//! Terminal User Interface module
//!
//! Provides a full-screen TUI dashboard using ratatui for:
//! - Interactive menu navigation
//! - Results display with scrolling
//! - Security grade visualization
//! - Status bar and help

pub mod app;
pub mod events;
pub mod ui;
pub mod widgets;

pub use app::{App, AppState, TuiRunner};
