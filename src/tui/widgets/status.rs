//! Status bar widget

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Widget},
};

/// Status bar mode/context
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StatusMode {
    Menu,
    Input,
    Loading,
    ResultsSections,  // Focus on sections panel
    ResultsContent,   // Focus on content panel
    Settings,
    Error,
}

/// Status bar widget showing context-sensitive help
pub struct StatusBar {
    mode: StatusMode,
    message: Option<String>,
}

impl StatusBar {
    pub fn new(mode: StatusMode) -> Self {
        Self {
            mode,
            message: None,
        }
    }

    pub fn with_message(mut self, message: &str) -> Self {
        self.message = Some(message.to_string());
        self
    }

    fn get_help_text(&self) -> Vec<(&str, &str)> {
        match self.mode {
            StatusMode::Menu => vec![
                ("↑↓", "Navigate"),
                ("Enter", "Select"),
                ("q", "Quit"),
            ],
            StatusMode::Input => vec![
                ("Enter", "Submit"),
                ("Esc", "Cancel"),
                ("←→", "Move cursor"),
            ],
            StatusMode::Loading => vec![
                ("Esc", "Cancel"),
            ],
            StatusMode::ResultsSections => vec![
                ("↑↓", "Section"),
                ("→", "View content"),
                ("Esc", "Back"),
                ("q", "Quit"),
            ],
            StatusMode::ResultsContent => vec![
                ("↑↓", "Scroll"),
                ("←", "Sections"),
                ("Tab", "Next section"),
                ("Esc", "Back"),
                ("q", "Quit"),
            ],
            StatusMode::Settings => vec![
                ("↑↓", "Navigate"),
                ("Enter", "Toggle"),
                ("Esc", "Back"),
            ],
            StatusMode::Error => vec![
                ("Enter", "Dismiss"),
                ("Esc", "Back"),
            ],
        }
    }
}

impl Widget for StatusBar {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let help_items = self.get_help_text();

        let mut spans = vec![];

        for (i, (key, action)) in help_items.iter().enumerate() {
            if i > 0 {
                spans.push(Span::styled(
                    "  │  ",
                    Style::default().fg(Color::DarkGray),
                ));
            }
            spans.push(Span::styled(
                format!(" {} ", key),
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::raw(" "));
            spans.push(Span::styled(*action, Style::default().fg(Color::White)));
        }

        // Add message if present
        if let Some(ref msg) = self.message {
            // Calculate remaining space
            let help_width: usize = spans.iter().map(|s| s.width()).sum();
            let msg_width = msg.len() + 4; // " | message "

            if help_width + msg_width < area.width as usize {
                spans.push(Span::styled(
                    "  │  ",
                    Style::default().fg(Color::DarkGray),
                ));
                spans.push(Span::styled(
                    msg.clone(),
                    Style::default().fg(Color::Yellow),
                ));
            }
        }

        let line = Line::from(spans);

        let block = Block::default()
            .borders(Borders::TOP)
            .border_style(Style::default().fg(Color::DarkGray));

        let paragraph = Paragraph::new(line).block(block);
        paragraph.render(area, buf);
    }
}

/// Header bar with title and optional domain info
pub struct HeaderBar<'a> {
    title: &'a str,
    domain: Option<&'a str>,
    version: &'a str,
}

impl<'a> HeaderBar<'a> {
    pub fn new(title: &'a str, version: &'a str) -> Self {
        Self {
            title,
            domain: None,
            version,
        }
    }

    pub fn with_domain(mut self, domain: &'a str) -> Self {
        self.domain = Some(domain);
        self
    }
}

impl Widget for HeaderBar<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let mut spans = vec![
            Span::styled(
                format!("  {} ", self.title),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("v{}", self.version),
                Style::default().fg(Color::DarkGray),
            ),
        ];

        if let Some(domain) = self.domain {
            spans.push(Span::styled(
                "  │  ",
                Style::default().fg(Color::DarkGray),
            ));
            spans.push(Span::styled(
                domain,
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ));
        }

        // Right-aligned quit hint
        let left_width: usize = spans.iter().map(|s| s.width()).sum();
        let quit_text = "[q] Quit  ";
        let padding = area.width as usize - left_width - quit_text.len();

        if padding > 0 {
            spans.push(Span::raw(" ".repeat(padding)));
        }
        spans.push(Span::styled(quit_text, Style::default().fg(Color::DarkGray)));

        let line = Line::from(spans);

        let block = Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(Color::DarkGray));

        let paragraph = Paragraph::new(line).block(block);
        paragraph.render(area, buf);
    }
}

/// Loading spinner animation
pub struct LoadingSpinner {
    frame: usize,
    message: String,
}

impl LoadingSpinner {
    const FRAMES: [&'static str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

    pub fn new(message: &str) -> Self {
        Self {
            frame: 0,
            message: message.to_string(),
        }
    }

    pub fn tick(&mut self) {
        self.frame = (self.frame + 1) % Self::FRAMES.len();
    }

    /// Get the current spinner frame character
    pub fn current_frame(&self) -> &'static str {
        Self::FRAMES[self.frame]
    }

    /// Get the loading message
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl Widget for &LoadingSpinner {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let spinner = LoadingSpinner::FRAMES[self.frame];
        let text = format!("{} {}", spinner, self.message);

        let line = Line::from(vec![
            Span::styled(
                spinner,
                Style::default().fg(Color::Cyan),
            ),
            Span::raw(" "),
            Span::styled(
                &self.message,
                Style::default().fg(Color::White),
            ),
        ]);

        // Center the loading message
        let x = area.x + (area.width.saturating_sub(text.len() as u16)) / 2;
        let y = area.y + area.height / 2;

        if y < area.y + area.height && x < area.x + area.width {
            buf.set_line(x, y, &line, area.width);
        }
    }
}
