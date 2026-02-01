//! Scrolling output display using Ratatui
//!
//! Displays output with smooth line-by-line scrolling, a fixed header,
//! and a status bar with navigation hints. Accounts for line wrapping
//! so that the status bar always stays visible at the bottom.

use ansi_to_tui::IntoText;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState},
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
pub fn display_paged<F>(header: &str, content: &str, on_save: F) -> PagerAction
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
    let result = run_pager(&mut terminal, header, content, on_save);

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

    // Popup state
    let mut show_save_popup = false;
    let mut save_input = String::new();
    // Placeholder default filename (would be better passed in, but we can default empty or generic)
    // We'll let the user type, or if empty, on_save can handle default.
    // Actually, let's make the input empty initially.

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

                // 1. Header
                let header_text = Line::from(vec![
                    Span::styled("◆", Style::default().fg(Color::Cyan)),
                    Span::raw(" "),
                    Span::styled(
                        header,
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]);
                let header_para = Paragraph::new(vec![
                    header_text,
                    Line::from(Span::styled(
                        "─".repeat(chunks[0].width as usize),
                        Style::default().add_modifier(Modifier::DIM),
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
                    // Render flash message
                    let bg_color = match color {
                        StatusColor::Cyan => Color::Cyan,
                        StatusColor::Green => Color::Green,
                        StatusColor::Red => Color::Red,
                    };
                    let text_color = match color {
                        StatusColor::Red => Color::White,
                        _ => Color::Black,
                    };

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

                    let status_widget = Paragraph::new(status_text)
                        .style(Style::default().bg(Color::White).fg(Color::Black));
                    f.render_widget(status_widget, status_area);
                }

                // 4. Save Popup
                if show_save_popup {
                    let area = centered_rect(60, 20, f.area());
                    f.render_widget(Clear, area); // Clear background

                    let block = Block::default()
                        .title(" Save Report ")
                        .borders(Borders::ALL)
                        .style(Style::default().bg(Color::DarkGray).fg(Color::White));

                    let inner_area = block.inner(area);
                    f.render_widget(block, area);

                    let vertical = Layout::default()
                        .direction(Direction::Vertical)
                        .constraints([
                            Constraint::Length(1), // Prompt
                            Constraint::Length(1), // Input
                            Constraint::Length(1), // Hint
                        ])
                        .margin(1)
                        .split(inner_area);

                    f.render_widget(
                        Paragraph::new("Enter filename (leave empty for default):"),
                        vertical[0],
                    );

                    f.render_widget(
                        Paragraph::new(format!("> {}_", save_input)).style(
                            Style::default()
                                .fg(Color::Cyan)
                                .add_modifier(Modifier::BOLD),
                        ),
                        vertical[1],
                    );

                    f.render_widget(
                        Paragraph::new("Enter: Confirm  Esc: Cancel")
                            .style(Style::default().fg(Color::Gray).add_modifier(Modifier::DIM)),
                        vertical[2],
                    );
                }
            })
            .unwrap();

        // Handle Events
        if event::poll(Duration::from_millis(100)).unwrap() {
            if let Event::Key(key) = event::read().unwrap() {
                if key.kind == KeyEventKind::Press {
                    if show_save_popup {
                        // Handle popup input
                        match key.code {
                            KeyCode::Enter => {
                                show_save_popup = false;
                                let input = if save_input.trim().is_empty() {
                                    None
                                } else {
                                    Some(save_input.clone())
                                };
                                let result = on_save(input);
                                flash = Some(match result {
                                    Ok(Some(path)) => (
                                        format!(" ✓ Saved: {} — press any key", path),
                                        StatusColor::Green,
                                    ),
                                    Ok(None) => (
                                        " Save cancelled — press any key".to_string(),
                                        StatusColor::Red,
                                    ),
                                    Err(e) => {
                                        (format!(" ✗ {} — press any key", e), StatusColor::Red)
                                    }
                                });
                                save_input.clear();
                            }
                            KeyCode::Esc => {
                                show_save_popup = false;
                                save_input.clear();
                                flash = Some((
                                    " Save cancelled — press any key".to_string(),
                                    StatusColor::Red,
                                ));
                            }
                            KeyCode::Char(c) => {
                                save_input.push(c);
                            }
                            KeyCode::Backspace => {
                                save_input.pop();
                            }
                            _ => {}
                        }
                    } else {
                        // Clear flash on any key
                        if flash.is_some() {
                            flash = None;
                            // Don't consume navigation keys just to clear flash?
                            // Original implementation: "any key clears the flash message",
                            // and "If the key was a navigation key, also apply it"
                        }

                        match key.code {
                            KeyCode::Char('q') | KeyCode::Esc => return PagerAction::Quit,
                            KeyCode::Char('n') | KeyCode::Char('N') => {
                                return PagerAction::NewCheck
                            }

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
                                let viewport = height.saturating_sub(4).max(1); // approx viewport
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

                            // Save Action - Open Popup
                            KeyCode::Char('s') | KeyCode::Char('S') => {
                                show_save_popup = true;
                                save_input.clear();
                            }

                            _ => {}
                        }
                    }
                }
            }
        }
    }
}

/// Helper function to create a centered rect using up certain percentage of the available rect `r`
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
