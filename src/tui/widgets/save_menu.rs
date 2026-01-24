//! Save menu widget for exporting results

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Widget},
};

/// Save menu options
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum SaveOption {
    #[default]
    PdfReport,
    CertificateChain,
    CalendarReminder,
    SaveAll,
    Cancel,
}

impl SaveOption {
    pub fn all() -> Vec<SaveOption> {
        vec![
            SaveOption::PdfReport,
            SaveOption::CertificateChain,
            SaveOption::CalendarReminder,
            SaveOption::SaveAll,
            SaveOption::Cancel,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            SaveOption::PdfReport => "PDF Report",
            SaveOption::CertificateChain => "Certificate Chain (PEM)",
            SaveOption::CalendarReminder => "Calendar Reminder (iCal)",
            SaveOption::SaveAll => "Save All",
            SaveOption::Cancel => "Cancel",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            SaveOption::PdfReport => "Branded PDF with certificate details",
            SaveOption::CertificateChain => "Full certificate chain in PEM format",
            SaveOption::CalendarReminder => "Expiry reminders at 30, 15, 5 days",
            SaveOption::SaveAll => "Export all formats",
            SaveOption::Cancel => "Return to results",
        }
    }

    pub fn is_separator(&self) -> bool {
        matches!(self, SaveOption::SaveAll)
    }
}

/// Save menu state
#[derive(Debug, Clone, Default)]
pub struct SaveMenuState {
    pub selected_index: usize,
    pub options: Vec<SaveOption>,
}

impl SaveMenuState {
    pub fn new() -> Self {
        Self {
            selected_index: 0,
            options: SaveOption::all(),
        }
    }

    pub fn next(&mut self) {
        self.selected_index = (self.selected_index + 1) % self.options.len();
    }

    pub fn previous(&mut self) {
        self.selected_index = if self.selected_index == 0 {
            self.options.len() - 1
        } else {
            self.selected_index - 1
        };
    }

    pub fn selected(&self) -> SaveOption {
        self.options[self.selected_index]
    }
}

/// Save menu widget
pub struct SaveMenuWidget;

impl SaveMenuWidget {
    pub fn new() -> Self {
        Self
    }

    /// Calculate centered area for the menu
    pub fn centered_area(area: Rect) -> Rect {
        let width = 40.min(area.width.saturating_sub(4));
        let height = 12.min(area.height.saturating_sub(4));
        let x = (area.width.saturating_sub(width)) / 2;
        let y = (area.height.saturating_sub(height)) / 2;

        Rect::new(x, y, width, height)
    }
}

impl Default for SaveMenuWidget {
    fn default() -> Self {
        Self::new()
    }
}

/// Render the save menu
pub fn render_save_menu(area: Rect, buf: &mut Buffer, state: &SaveMenuState) {
    let menu_area = SaveMenuWidget::centered_area(area);

    // Clear background
    Clear.render(menu_area, buf);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(" Save Results ")
        .title_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));

    let inner = block.inner(menu_area);
    block.render(menu_area, buf);

    let mut items = Vec::new();

    for (i, option) in state.options.iter().enumerate() {
        // Add separator before SaveAll
        if option.is_separator() {
            items.push(ListItem::new(Line::from(vec![
                Span::styled(
                    "  ────────────────────────────",
                    Style::default().fg(Color::DarkGray),
                ),
            ])));
        }

        let is_selected = i == state.selected_index;
        let prefix = if is_selected { "> " } else { "  " };

        let style = if is_selected {
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
        } else if matches!(option, SaveOption::Cancel) {
            Style::default().fg(Color::Gray)
        } else {
            Style::default().fg(Color::White)
        };

        items.push(ListItem::new(Line::from(vec![
            Span::styled(prefix, style),
            Span::styled(option.label(), style),
        ])));
    }

    let list = List::new(items);
    list.render(inner, buf);
}

/// Save path input state
#[derive(Debug, Clone)]
pub struct SavePathState {
    pub path: String,
    pub cursor: usize,
    pub save_option: SaveOption,
    pub preview_files: Vec<String>,
    pub error: Option<String>,
}

impl SavePathState {
    pub fn new(option: SaveOption, domain: &str) -> Self {
        let date = chrono::Utc::now().format("%Y%m%d").to_string();
        let safe_domain = domain.replace('.', "_").replace(':', "_");

        let preview_files = match option {
            SaveOption::PdfReport => vec![
                format!("{}_ssl_report_{}.pdf", safe_domain, date),
            ],
            SaveOption::CertificateChain => vec![
                format!("{}_chain.pem", safe_domain),
            ],
            SaveOption::CalendarReminder => vec![
                format!("{}_ssl_expiry.ics", safe_domain),
            ],
            SaveOption::SaveAll => vec![
                format!("{}_ssl_report_{}.pdf", safe_domain, date),
                format!("{}_chain.pem", safe_domain),
                format!("{}_ssl_expiry.ics", safe_domain),
            ],
            SaveOption::Cancel => vec![],
        };

        Self {
            path: "./".to_string(),
            cursor: 2,
            save_option: option,
            preview_files,
            error: None,
        }
    }

    pub fn insert(&mut self, c: char) {
        self.path.insert(self.cursor, c);
        self.cursor += 1;
        self.error = None;
    }

    pub fn delete_backward(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
            self.path.remove(self.cursor);
            self.error = None;
        }
    }

    pub fn delete_forward(&mut self) {
        if self.cursor < self.path.len() {
            self.path.remove(self.cursor);
            self.error = None;
        }
    }

    pub fn move_left(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
        }
    }

    pub fn move_right(&mut self) {
        if self.cursor < self.path.len() {
            self.cursor += 1;
        }
    }

    pub fn move_home(&mut self) {
        self.cursor = 0;
    }

    pub fn move_end(&mut self) {
        self.cursor = self.path.len();
    }

    pub fn set_error(&mut self, error: &str) {
        self.error = Some(error.to_string());
    }
}

/// Render save path dialog
pub fn render_save_path_dialog(area: Rect, buf: &mut Buffer, state: &SavePathState) {
    let dialog_height = 8 + state.preview_files.len() as u16;
    let dialog_width = 55.min(area.width.saturating_sub(4));
    let x = (area.width.saturating_sub(dialog_width)) / 2;
    let y = (area.height.saturating_sub(dialog_height)) / 2;

    let dialog_area = Rect::new(x, y, dialog_width, dialog_height);

    // Clear background
    Clear.render(dialog_area, buf);

    let border_color = if state.error.is_some() {
        Color::Red
    } else {
        Color::Cyan
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color))
        .title(" Save Location ")
        .title_style(Style::default().fg(border_color).add_modifier(Modifier::BOLD));

    let inner = block.inner(dialog_area);
    block.render(dialog_area, buf);

    let mut lines = vec![];
    lines.push(Line::from(""));

    // Input field with cursor
    let mut input_spans = vec![Span::raw("  [")];

    let (before, after) = state.path.split_at(state.cursor);
    let (cursor_char, rest) = if after.is_empty() {
        (" ", "")
    } else {
        after.split_at(1)
    };

    input_spans.push(Span::styled(before, Style::default().fg(Color::White)));
    input_spans.push(Span::styled(
        cursor_char,
        Style::default().bg(Color::White).fg(Color::Black),
    ));
    input_spans.push(Span::styled(rest, Style::default().fg(Color::White)));

    // Pad to fill the field
    let current_len = before.len() + 1 + rest.len();
    let max_len = (dialog_width as usize).saturating_sub(8);
    if current_len < max_len {
        input_spans.push(Span::raw(" ".repeat(max_len - current_len)));
    }
    input_spans.push(Span::raw("]"));

    lines.push(Line::from(input_spans));
    lines.push(Line::from(""));

    // Error message if any
    if let Some(ref error) = state.error {
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled("Error: ", Style::default().fg(Color::Red)),
            Span::styled(error.clone(), Style::default().fg(Color::Red)),
        ]));
        lines.push(Line::from(""));
    }

    // Preview files
    lines.push(Line::from(vec![
        Span::styled("  Files will be saved as:", Style::default().fg(Color::DarkGray)),
    ]));

    for file in &state.preview_files {
        lines.push(Line::from(vec![
            Span::styled("  - ", Style::default().fg(Color::Cyan)),
            Span::styled(file.clone(), Style::default().fg(Color::Yellow)),
        ]));
    }

    let paragraph = Paragraph::new(lines);
    paragraph.render(inner, buf);
}

/// Saving overlay state
#[derive(Debug, Clone)]
pub struct SavingState {
    pub message: String,
    pub progress: Option<(usize, usize)>, // (current, total)
}

impl SavingState {
    pub fn new(message: &str) -> Self {
        Self {
            message: message.to_string(),
            progress: None,
        }
    }

    pub fn with_progress(mut self, current: usize, total: usize) -> Self {
        self.progress = Some((current, total));
        self
    }
}

/// Render saving overlay
pub fn render_saving_overlay(area: Rect, buf: &mut Buffer, state: &SavingState) {
    let dialog_width = 40.min(area.width.saturating_sub(4));
    let dialog_height = 5;
    let x = (area.width.saturating_sub(dialog_width)) / 2;
    let y = (area.height.saturating_sub(dialog_height)) / 2;

    let dialog_area = Rect::new(x, y, dialog_width, dialog_height);

    // Clear background
    Clear.render(dialog_area, buf);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(" Saving ")
        .title_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));

    let inner = block.inner(dialog_area);
    block.render(dialog_area, buf);

    let mut lines = vec![];
    lines.push(Line::from(""));

    let mut message_spans = vec![
        Span::styled("  ", Style::default()),
        Span::styled("...", Style::default().fg(Color::Cyan)),
        Span::raw(" "),
        Span::styled(state.message.clone(), Style::default().fg(Color::White)),
    ];

    if let Some((current, total)) = state.progress {
        message_spans.push(Span::styled(
            format!(" ({}/{})", current, total),
            Style::default().fg(Color::DarkGray),
        ));
    }

    lines.push(Line::from(message_spans));

    let paragraph = Paragraph::new(lines);
    paragraph.render(inner, buf);
}
