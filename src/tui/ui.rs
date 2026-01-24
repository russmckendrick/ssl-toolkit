//! Main UI rendering

use crate::export::ExportResult;
use crate::tui::app::{App, AppState};
use crate::tui::widgets::{
    input::{render_input, InputDialog},
    menu::MenuWidget,
    results::ResultsWidget,
    save_menu::{render_save_menu, render_save_path_dialog, render_saving_overlay},
    status::{HeaderBar, LoadingSpinner, StatusBar, StatusMode},
};
use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, StatefulWidget, Widget, Wrap},
    Frame,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Main draw function
pub fn draw(f: &mut Frame, app: &mut App) {
    let size = f.area();

    // Main layout: header, content, status bar
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),  // Header
            Constraint::Min(10),    // Content
            Constraint::Length(2),  // Status bar
        ])
        .split(size);

    // Render header
    let domain = if !app.current_domain.is_empty() && matches!(app.state, AppState::Results | AppState::Checking) {
        Some(format!("{}:{}", app.current_domain, app.current_port))
    } else {
        None
    };

    let header = if let Some(ref d) = domain {
        HeaderBar::new("SSL Toolkit", VERSION).with_domain(d)
    } else {
        HeaderBar::new("SSL Toolkit", VERSION)
    };
    f.render_widget(header, chunks[0]);

    // Clone state info we need for dialogs before the match
    let error_msg = if let AppState::Error(msg) = &app.state {
        Some(msg.clone())
    } else {
        None
    };

    let save_complete_results = if let AppState::SaveComplete(ref results) = app.state {
        Some(results.clone())
    } else {
        None
    };

    // Clone input states for dialogs
    let domain_input = app.domain_input.clone();
    let port_input = app.port_input.clone();
    let file_input = app.file_input.clone();
    let second_domain_input = app.second_domain_input.clone();

    // Render content based on state
    match app.state {
        AppState::MainMenu => {
            render_main_menu(f, chunks[1], app);
        }
        AppState::InputDomain => {
            render_main_menu(f, chunks[1], app);
            render_input_dialog(f, size, &domain_input);
        }
        AppState::InputPort => {
            render_main_menu(f, chunks[1], app);
            render_input_dialog(f, size, &port_input);
        }
        AppState::InputFile => {
            render_main_menu(f, chunks[1], app);
            render_input_dialog(f, size, &file_input);
        }
        AppState::InputSecondDomain => {
            render_main_menu(f, chunks[1], app);
            render_input_dialog(f, size, &second_domain_input);
        }
        AppState::Checking => {
            render_loading(f, chunks[1], &app.spinner);
        }
        AppState::Results => {
            render_results(f, chunks[1], app);
        }
        AppState::Settings => {
            render_settings(f, chunks[1], app);
        }
        AppState::Error(_) => {
            render_main_menu(f, chunks[1], app);
            if let Some(msg) = error_msg {
                render_error_dialog(f, size, &msg);
            }
        }
        AppState::SaveMenu => {
            render_results(f, chunks[1], app);
            render_save_menu(size, f.buffer_mut(), &app.save_menu);
        }
        AppState::SavePath => {
            render_results(f, chunks[1], app);
            if let Some(ref path_state) = app.save_path {
                render_save_path_dialog(size, f.buffer_mut(), path_state);
            }
        }
        AppState::Saving => {
            render_results(f, chunks[1], app);
            if let Some(ref saving_state) = app.saving_state {
                render_saving_overlay(size, f.buffer_mut(), saving_state);
            }
        }
        AppState::SaveComplete(_) => {
            render_results(f, chunks[1], app);
            if let Some(results) = save_complete_results {
                render_save_complete_dialog(f, size, &results);
            }
        }
        AppState::Quit => {}
    }

    // Render status bar
    let status_mode = match app.state {
        AppState::MainMenu => StatusMode::Menu,
        AppState::InputDomain | AppState::InputPort | AppState::InputFile | AppState::InputSecondDomain => {
            StatusMode::Input
        }
        AppState::Checking => StatusMode::Loading,
        AppState::Results => {
            use crate::tui::widgets::results::ResultsFocus;
            match app.results.focus {
                ResultsFocus::Sections => StatusMode::ResultsSections,
                ResultsFocus::Content => StatusMode::ResultsContent,
            }
        }
        AppState::Settings => StatusMode::Settings,
        AppState::Error(_) => StatusMode::Error,
        AppState::SaveMenu => StatusMode::SaveMenu,
        AppState::SavePath => StatusMode::SavePath,
        AppState::Saving => StatusMode::Saving,
        AppState::SaveComplete(_) => StatusMode::SaveComplete,
        AppState::Quit => StatusMode::Menu,
    };

    let status = StatusBar::new(status_mode);
    f.render_widget(status, chunks[2]);
}

fn render_main_menu(f: &mut Frame, area: Rect, app: &mut App) {
    // Center the menu with some padding
    let menu_width = 60.min(area.width.saturating_sub(4));
    let menu_height = 12.min(area.height.saturating_sub(4));

    let x = (area.width.saturating_sub(menu_width)) / 2 + area.x;
    let y = (area.height.saturating_sub(menu_height)) / 2 + area.y;

    let menu_area = Rect::new(x, y, menu_width, menu_height);

    let menu = MenuWidget::new().block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title(" Main Menu ")
            .title_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
    );

    f.render_stateful_widget(menu, menu_area, &mut app.menu);
}

fn render_input_dialog(f: &mut Frame, area: Rect, input: &crate::tui::widgets::input::InputState) {
    let dialog = InputDialog::new(&input.prompt).width(50);
    let dialog_area = dialog.centered_area(area);

    // Clear background
    f.render_widget(Clear, dialog_area);

    // Render input
    render_input(dialog_area, f.buffer_mut(), input);
}

fn render_loading(f: &mut Frame, area: Rect, spinner: &LoadingSpinner) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(" Loading ");

    let inner = block.inner(area);
    f.render_widget(block, area);

    // Simple centered spinner with message
    let spinner_text = spinner.current_frame();
    let message = spinner.message();

    let line = Line::from(vec![
        Span::styled(spinner_text, Style::default().fg(Color::Cyan)),
        Span::raw(" "),
        Span::styled(message, Style::default().fg(Color::White)),
    ]);

    // Center the loading message
    let line_width = line.width() as u16;
    let x = inner.x + inner.width.saturating_sub(line_width) / 2;
    let y = inner.y + inner.height / 2;

    if y < inner.y + inner.height && x < inner.x + inner.width {
        f.buffer_mut().set_line(x, y, &line, inner.width);
    }
}

fn render_results(f: &mut Frame, area: Rect, app: &mut App) {
    if let Some(ref data) = app.results_data {
        let results = ResultsWidget::new(data);
        f.render_stateful_widget(results, area, &mut app.results);
    } else {
        let paragraph = Paragraph::new("No results available")
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(paragraph, area);
    }
}

fn render_settings(f: &mut Frame, area: Rect, app: &App) {
    // Center the settings panel
    let panel_width = 50.min(area.width.saturating_sub(4));
    let panel_height = 14.min(area.height.saturating_sub(4));

    let x = (area.width.saturating_sub(panel_width)) / 2 + area.x;
    let y = (area.height.saturating_sub(panel_height)) / 2 + area.y;

    let panel_area = Rect::new(x, y, panel_width, panel_height);

    // Pre-format strings to extend their lifetime
    let output_format_str = format!("{}", app.output_format);
    let verbose_str = format_bool(app.verbose);
    let skip_dns_str = format_bool(app.skip_dns);
    let skip_ct_str = format_bool(app.skip_ct);
    let skip_ocsp_str = format_bool(app.skip_ocsp);

    let items: Vec<ListItem> = vec![
        create_setting_item("Output Format", &output_format_str, app.settings_index == 0),
        create_setting_item("Verbose Mode", verbose_str, app.settings_index == 1),
        create_setting_item("Skip DNS", skip_dns_str, app.settings_index == 2),
        create_setting_item("Skip CT Logs", skip_ct_str, app.settings_index == 3),
        create_setting_item("Skip OCSP", skip_ocsp_str, app.settings_index == 4),
        ListItem::new(Line::from(vec![
            Span::raw("  "),
            Span::styled(
                "← Back to menu",
                if app.settings_index == 5 {
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Gray)
                },
            ),
        ])),
    ];

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title(" Settings ")
            .title_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
    );

    f.render_widget(list, panel_area);
}

fn create_setting_item<'a>(label: &'a str, value: &'a str, selected: bool) -> ListItem<'a> {
    let style = if selected {
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::White)
    };

    let prefix = if selected { "> " } else { "  " };

    ListItem::new(Line::from(vec![
        Span::raw(prefix),
        Span::styled(format!("{}: ", label), style),
        Span::styled(value, Style::default().fg(Color::Yellow)),
    ]))
}

fn format_bool(value: bool) -> &'static str {
    if value { "Yes" } else { "No" }
}

fn render_error_dialog(f: &mut Frame, area: Rect, message: &str) {
    let dialog_width = 60.min(area.width.saturating_sub(4));
    let dialog_height = 8.min(area.height.saturating_sub(4));

    let x = (area.width.saturating_sub(dialog_width)) / 2;
    let y = (area.height.saturating_sub(dialog_height)) / 2;

    let dialog_area = Rect::new(x, y, dialog_width, dialog_height);

    f.render_widget(Clear, dialog_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red))
        .title(" Error ")
        .title_style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD));

    let inner = block.inner(dialog_area);

    let text = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  ✗ ", Style::default().fg(Color::Red)),
            Span::raw(message),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "  Press Enter or Esc to dismiss",
                Style::default().fg(Color::DarkGray),
            ),
        ]),
    ];

    let paragraph = Paragraph::new(text).wrap(Wrap { trim: false });

    f.render_widget(block, dialog_area);
    f.render_widget(paragraph, inner);
}

fn render_save_complete_dialog(f: &mut Frame, area: Rect, results: &[ExportResult]) {
    let success_count = results.iter().filter(|r| r.success).count();
    let fail_count = results.len() - success_count;

    let dialog_height = (6 + results.len() * 2) as u16;
    let dialog_width = 60.min(area.width.saturating_sub(4));
    let dialog_height = dialog_height.min(area.height.saturating_sub(4));

    let x = (area.width.saturating_sub(dialog_width)) / 2;
    let y = (area.height.saturating_sub(dialog_height)) / 2;

    let dialog_area = Rect::new(x, y, dialog_width, dialog_height);

    f.render_widget(Clear, dialog_area);

    let (title, border_color) = if fail_count == 0 {
        (" Export Complete ", Color::Green)
    } else if success_count == 0 {
        (" Export Failed ", Color::Red)
    } else {
        (" Export Partial ", Color::Yellow)
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color))
        .title(title)
        .title_style(Style::default().fg(border_color).add_modifier(Modifier::BOLD));

    let inner = block.inner(dialog_area);

    let mut text = vec![Line::from("")];

    for result in results {
        let (icon, color) = if result.success {
            ("✓", Color::Green)
        } else {
            ("✗", Color::Red)
        };

        text.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(icon, Style::default().fg(color)),
            Span::raw(" "),
            Span::styled(result.export_type.label(), Style::default().add_modifier(Modifier::BOLD)),
        ]));

        if result.success {
            // Truncate path if too long
            let path = if result.path.len() > 45 {
                format!("...{}", &result.path[result.path.len() - 42..])
            } else {
                result.path.clone()
            };
            text.push(Line::from(vec![
                Span::raw("    "),
                Span::styled(path, Style::default().fg(Color::DarkGray)),
            ]));
        } else if let Some(ref error) = result.error {
            text.push(Line::from(vec![
                Span::raw("    "),
                Span::styled(error.clone(), Style::default().fg(Color::Red)),
            ]));
        }
    }

    text.push(Line::from(""));
    text.push(Line::from(vec![
        Span::styled(
            "  Press Enter or Esc to continue",
            Style::default().fg(Color::DarkGray),
        ),
    ]));

    let paragraph = Paragraph::new(text).wrap(Wrap { trim: false });

    f.render_widget(block, dialog_area);
    f.render_widget(paragraph, inner);
}
