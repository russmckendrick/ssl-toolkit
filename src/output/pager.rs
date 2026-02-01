//! Scrolling output display using Ratatui
//!
//! Displays output with smooth line-by-line scrolling, a fixed header,
//! and a status bar with navigation hints. Accounts for line wrapping
//! so that the status bar always stays visible at the bottom.

use super::interactive;
use ansi_to_tui::IntoText;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState},
    Terminal,
};
use std::io::{stdout, Stdout};
use std::time::Duration;

/// Action the user chose when exiting the pager
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PagerAction {
    /// User pressed q/Esc to quit
    Quit,
    /// User pressed n to run a new check
    NewCheck,
}

/// Status bar color for flash messages
#[allow(dead_code)]
#[derive(Clone, Copy)]
enum StatusColor {
    Cyan,
    Green,
    Red,
}

/// Display text content with smooth scrolling.
///
/// `default_filename` is shown as the initial value in the save-report
/// prompt (press `s`). Pass an empty string to disable save.
pub fn display_paged<F>(
    header: &str,
    content: &str,
    default_filename: &str,
    on_save: F,
) -> PagerAction
where
    F: Fn(Option<String>) -> Result<Option<String>, String>,
{
    // Setup terminal
    enable_raw_mode().unwrap();
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen).unwrap();
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).unwrap();

    // Run pager loop
    let result = run_pager(&mut terminal, header, content, default_filename, on_save);

    // Restore terminal
    disable_raw_mode().unwrap();
    execute!(std::io::stdout(), LeaveAlternateScreen).unwrap();
    terminal.show_cursor().unwrap();

    result
}

fn run_pager<F>(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    header: &str,
    content: &str,
    default_filename: &str,
    on_save: F,
) -> PagerAction
where
    F: Fn(Option<String>) -> Result<Option<String>, String>,
{
    let lines: Vec<&str> = content.lines().collect();
    let total_lines = lines.len();

    // Determine content width for wrapping calculation
    // Note: This is an approximation since Ratatui handles wrapping dynamically,
    // but we need it for scrollbar state.
    // We'll trust Ratatui's Paragraph wrapping for display.

    let mut scroll_offset = 0;
    let mut scrollbar_state = ScrollbarState::default().content_length(total_lines);

    // Flash message state
    let mut flash: Option<(String, StatusColor)> = None;

    loop {
        terminal
            .draw(|f| {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(2), // Header + Separator
                        Constraint::Min(0),    // Content
                        Constraint::Length(1), // Status Bar
                    ])
                    .split(f.area());

                // Tokyo Night Storm palette constants
                let tn_primary = Color::Rgb(122, 162, 247); // #7aa2f7
                let tn_border = Color::Rgb(86, 95, 137); // #565f89
                let tn_bg = Color::Rgb(36, 40, 59); // #24283b

                // 1. Header
                let header_text = Line::from(vec![
                    Span::styled("◆", Style::default().fg(tn_primary)),
                    Span::raw(" "),
                    Span::styled(
                        header,
                        Style::default().fg(tn_primary).add_modifier(Modifier::BOLD),
                    ),
                ]);
                let header_para = Paragraph::new(vec![
                    header_text,
                    Line::from(Span::styled(
                        "─".repeat(chunks[0].width as usize),
                        Style::default().fg(tn_border),
                    )),
                ]);
                f.render_widget(header_para, chunks[0]);

                // 2. Content
                // Convert ANSI string to Ratatui text
                let content_text = content
                    .into_text()
                    .unwrap_or_else(|_| ratatui::text::Text::raw(content));
                let content_widget = Paragraph::new(content_text)
                    .scroll((scroll_offset as u16, 0))
                    .wrap(ratatui::widgets::Wrap { trim: false }); // Wrap lines
                f.render_widget(content_widget, chunks[1]);

                // Update scrollbar state based on viewport height
                // Note: Paragraph line count might differ from logical lines if wrapped,
                // but for simplicity we track logical lines or let user scroll visually.
                // A more robust approach wraps text manually to count visual lines,
                // but Ratatui's scroll is line-based.
                // We'll stick to logical line scrolling for now or we can count visual lines if needed.
                // To keep it simple and stable: map scroll_offset to logical lines.
                // If text wraps, Ratatui hides lines at the top.

                // Draw Scrollbar
                let scrollbar = Scrollbar::default()
                    .orientation(ScrollbarOrientation::VerticalRight)
                    .begin_symbol(Some("↑"))
                    .end_symbol(Some("↓"));

                // Estimate visual lines for scrollbar correctness
                // This is expensive to calculate perfectly every frame without cache,
                // so we approximate or use logical lines.
                // Let's use logical lines for scroll state.
                scrollbar_state = scrollbar_state
                    .content_length(total_lines)
                    .position(scroll_offset);

                f.render_stateful_widget(scrollbar, chunks[1], &mut scrollbar_state);

                // 3. Status Bar
                let status_area = chunks[2];
                if let Some((ref msg, color)) = flash {
                    // Render flash message with Tokyo Night colours
                    let bg_color = match color {
                        StatusColor::Cyan => Color::Rgb(122, 162, 247), // primary
                        StatusColor::Green => Color::Rgb(158, 206, 106), // pass green
                        StatusColor::Red => Color::Rgb(247, 118, 142),  // fail red
                    };
                    let text_color = Color::Rgb(36, 40, 59); // background as text

                    let padded_msg = format!("{:<width$}", msg, width = status_area.width as usize);
                    let status_widget = Paragraph::new(padded_msg)
                        .style(Style::default().bg(bg_color).fg(text_color));
                    f.render_widget(status_widget, status_area);
                } else {
                    // Normal Status Bar
                    // Left: "Lines X-Y of Z (Pct)" or "All content shown"
                    // Right: Hints

                    // Note: calculating exact visual lines displayed is tricky with wrapping.
                    // We'll show simplistic info: "Line X of Y"
                    let pct = if total_lines > 0 {
                        (scroll_offset * 100) / total_lines
                    } else {
                        100
                    };

                    let status_left =
                        format!(" Line {}/{} ({}%)", scroll_offset + 1, total_lines, pct);
                    let status_right = " ↑↓: scroll  Space: page  s: save  n: new  q: quit ";

                    // Pad center
                    let available_width = status_area.width as usize;
                    let left_len = status_left.len();
                    let right_len = status_right.len();

                    let gap = available_width.saturating_sub(left_len + right_len);
                    let status_text = format!("{}{}{}", status_left, " ".repeat(gap), status_right);

                    let status_widget =
                        Paragraph::new(status_text).style(Style::default().bg(tn_border).fg(tn_bg));
                    f.render_widget(status_widget, status_area);
                }
            })
            .unwrap();

        // Handle Events
        if event::poll(Duration::from_millis(100)).unwrap() {
            if let Event::Key(key) = event::read().unwrap() {
                if key.kind == KeyEventKind::Press {
                    // Clear flash on any key
                    if flash.is_some() {
                        flash = None;
                    }

                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => return PagerAction::Quit,
                        KeyCode::Char('n') | KeyCode::Char('N') => return PagerAction::NewCheck,

                        // Scrolling
                        KeyCode::Down | KeyCode::Char('j') | KeyCode::Enter => {
                            if scroll_offset < total_lines.saturating_sub(1) {
                                scroll_offset += 1;
                            }
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            scroll_offset = scroll_offset.saturating_sub(1);
                        }
                        KeyCode::PageDown | KeyCode::Char(' ') => {
                            let height = terminal.size().unwrap().height as usize;
                            let viewport = height.saturating_sub(4).max(1);
                            scroll_offset =
                                (scroll_offset + viewport).min(total_lines.saturating_sub(1));
                        }
                        KeyCode::PageUp | KeyCode::Char('b') => {
                            let height = terminal.size().unwrap().height as usize;
                            let viewport = height.saturating_sub(4).max(1);
                            scroll_offset = scroll_offset.saturating_sub(viewport);
                        }
                        KeyCode::Home | KeyCode::Char('g') => {
                            scroll_offset = 0;
                        }
                        KeyCode::End | KeyCode::Char('G') => {
                            scroll_offset = total_lines.saturating_sub(1);
                        }

                        // Save — leave alternate screen, show inquire prompt
                        KeyCode::Char('s') | KeyCode::Char('S') => {
                            // Temporarily exit the pager's alternate screen
                            disable_raw_mode().unwrap();
                            execute!(std::io::stdout(), LeaveAlternateScreen).unwrap();
                            terminal.show_cursor().unwrap();

                            // Show the interactive save prompt with file explorer
                            let save_path =
                                interactive::prompt_report_path(default_filename).unwrap_or(None);

                            // Process the result through on_save
                            flash = Some(match save_path {
                                Some(path) => match on_save(Some(path)) {
                                    Ok(Some(saved)) => (
                                        format!(" ✓ Saved: {} — press any key", saved),
                                        StatusColor::Green,
                                    ),
                                    Ok(None) => (
                                        " Save cancelled — press any key".to_string(),
                                        StatusColor::Red,
                                    ),
                                    Err(e) => {
                                        (format!(" ✗ {} — press any key", e), StatusColor::Red)
                                    }
                                },
                                None => (
                                    " Save cancelled — press any key".to_string(),
                                    StatusColor::Red,
                                ),
                            });

                            // Re-enter the pager's alternate screen
                            enable_raw_mode().unwrap();
                            execute!(std::io::stdout(), EnterAlternateScreen).unwrap();
                            // Force a full redraw after returning from the prompt
                            terminal.clear().unwrap();
                        }

                        _ => {}
                    }
                }
            }
        }
    }
}
