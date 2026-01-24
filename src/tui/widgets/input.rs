//! Input widget for text entry

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Widget},
};

/// Input field state
#[derive(Debug, Clone)]
pub struct InputState {
    /// Current input value
    pub value: String,
    /// Cursor position
    pub cursor: usize,
    /// Prompt text
    pub prompt: String,
    /// Placeholder text
    pub placeholder: String,
    /// Whether input is focused
    pub focused: bool,
    /// Error message if any
    pub error: Option<String>,
    /// Whether the input is for a password
    pub password: bool,
}

impl Default for InputState {
    fn default() -> Self {
        Self {
            value: String::new(),
            cursor: 0,
            prompt: "Enter value".to_string(),
            placeholder: String::new(),
            focused: true,
            error: None,
            password: false,
        }
    }
}

impl InputState {
    pub fn new(prompt: &str) -> Self {
        Self {
            prompt: prompt.to_string(),
            ..Default::default()
        }
    }

    pub fn with_placeholder(mut self, placeholder: &str) -> Self {
        self.placeholder = placeholder.to_string();
        self
    }

    pub fn with_default(mut self, default: &str) -> Self {
        self.value = default.to_string();
        self.cursor = default.len();
        self
    }

    pub fn insert(&mut self, c: char) {
        self.value.insert(self.cursor, c);
        self.cursor += 1;
        self.error = None;
    }

    pub fn delete_backward(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
            self.value.remove(self.cursor);
            self.error = None;
        }
    }

    pub fn delete_forward(&mut self) {
        if self.cursor < self.value.len() {
            self.value.remove(self.cursor);
            self.error = None;
        }
    }

    pub fn move_left(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
        }
    }

    pub fn move_right(&mut self) {
        if self.cursor < self.value.len() {
            self.cursor += 1;
        }
    }

    pub fn move_home(&mut self) {
        self.cursor = 0;
    }

    pub fn move_end(&mut self) {
        self.cursor = self.value.len();
    }

    pub fn clear(&mut self) {
        self.value.clear();
        self.cursor = 0;
        self.error = None;
    }

    pub fn set_error(&mut self, error: &str) {
        self.error = Some(error.to_string());
    }

    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }
}

/// Input widget
pub struct InputWidget<'a> {
    block: Option<Block<'a>>,
}

impl<'a> InputWidget<'a> {
    pub fn new() -> Self {
        Self { block: None }
    }

    pub fn block(mut self, block: Block<'a>) -> Self {
        self.block = Some(block);
        self
    }
}

impl<'a> Default for InputWidget<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl Widget for InputWidget<'_> {
    fn render(self, _area: Rect, _buf: &mut Buffer) {
        // Stateless render not used
    }
}

/// Render the input widget with state
pub fn render_input(area: Rect, buf: &mut Buffer, state: &InputState) {
    // Clear the area first
    Clear.render(area, buf);

    // Create the display value
    let display_value = if state.password {
        "*".repeat(state.value.len())
    } else if state.value.is_empty() {
        state.placeholder.clone()
    } else {
        state.value.clone()
    };

    let value_style = if state.value.is_empty() && !state.placeholder.is_empty() {
        Style::default().fg(Color::DarkGray)
    } else {
        Style::default().fg(Color::White)
    };

    // Build the input line with cursor
    let mut spans = vec![];

    if state.focused && !state.value.is_empty() {
        let (before, after) = state.value.split_at(state.cursor);
        let (cursor_char, rest) = if after.is_empty() {
            (" ", "")
        } else {
            after.split_at(1)
        };

        if state.password {
            spans.push(Span::styled("*".repeat(before.len()), value_style));
            spans.push(Span::styled(
                if cursor_char == " " { " " } else { "*" },
                Style::default().bg(Color::White).fg(Color::Black),
            ));
            spans.push(Span::styled("*".repeat(rest.len()), value_style));
        } else {
            spans.push(Span::styled(before, value_style));
            spans.push(Span::styled(
                cursor_char,
                Style::default().bg(Color::White).fg(Color::Black),
            ));
            spans.push(Span::styled(rest, value_style));
        }
    } else if state.focused && state.value.is_empty() {
        spans.push(Span::styled(
            " ",
            Style::default().bg(Color::White).fg(Color::Black),
        ));
        if !state.placeholder.is_empty() {
            spans.push(Span::styled(&state.placeholder[1.min(state.placeholder.len())..], Style::default().fg(Color::DarkGray)));
        }
    } else {
        spans.push(Span::styled(display_value, value_style));
    }

    let input_line = Line::from(spans);

    // Create block with prompt
    let border_color = if state.error.is_some() {
        Color::Red
    } else if state.focused {
        Color::Cyan
    } else {
        Color::Gray
    };

    let title = if let Some(ref error) = state.error {
        format!(" {} - {} ", state.prompt, error)
    } else {
        format!(" {} ", state.prompt)
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color))
        .title(Span::styled(
            title,
            Style::default()
                .fg(border_color)
                .add_modifier(Modifier::BOLD),
        ));

    let paragraph = Paragraph::new(input_line).block(block);
    paragraph.render(area, buf);
}

/// Input dialog that centers in the terminal
pub struct InputDialog<'a> {
    pub title: &'a str,
    pub width: u16,
    pub height: u16,
}

impl<'a> InputDialog<'a> {
    pub fn new(title: &'a str) -> Self {
        Self {
            title,
            width: 50,
            height: 5,
        }
    }

    pub fn width(mut self, width: u16) -> Self {
        self.width = width;
        self
    }

    /// Calculate centered area for the dialog
    pub fn centered_area(&self, area: Rect) -> Rect {
        let width = self.width.min(area.width.saturating_sub(4));
        let height = self.height.min(area.height.saturating_sub(4));
        let x = (area.width.saturating_sub(width)) / 2;
        let y = (area.height.saturating_sub(height)) / 2;

        Rect::new(x, y, width, height)
    }
}
