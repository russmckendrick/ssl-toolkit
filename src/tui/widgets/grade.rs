//! Security grade widget

use crate::certificate::{security::FactorStatus, SecurityGrade};
use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Widget},
};

/// Security grade display widget
pub struct GradeWidget<'a> {
    grade: &'a SecurityGrade,
}

impl<'a> GradeWidget<'a> {
    pub fn new(grade: &'a SecurityGrade) -> Self {
        Self { grade }
    }

    fn grade_color(&self) -> Color {
        match self.grade.grade {
            'A' => Color::Green,
            'B' => Color::Cyan,
            'C' => Color::Yellow,
            'D' => Color::Rgb(255, 165, 0), // Orange
            _ => Color::Red,
        }
    }
}

impl Widget for GradeWidget<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(7), // Grade box
                Constraint::Min(3),    // Factors
            ])
            .split(area);

        // Render grade box
        self.render_grade_box(chunks[0], buf);

        // Render factors
        self.render_factors(chunks[1], buf);
    }
}

impl GradeWidget<'_> {
    fn render_grade_box(&self, area: Rect, buf: &mut Buffer) {
        let grade_display = self.grade.display();
        let grade_color = self.grade_color();

        // ASCII art for grade
        let grade_lines = create_grade_ascii(&grade_display, grade_color);

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title(" Security Grade ");

        let inner = block.inner(area);
        block.render(area, buf);

        // Center the grade display
        let content_height = grade_lines.len() as u16;
        let start_y = inner.y + (inner.height.saturating_sub(content_height)) / 2;

        for (i, line) in grade_lines.iter().enumerate() {
            let y = start_y + i as u16;
            if y >= inner.y + inner.height {
                break;
            }
            // Center horizontally
            let line_width = line.width() as u16;
            let x = inner.x + (inner.width.saturating_sub(line_width)) / 2;
            buf.set_line(x, y, line, inner.width);
        }
    }

    fn render_factors(&self, area: Rect, buf: &mut Buffer) {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title(" Grade Factors ");

        let inner = block.inner(area);
        block.render(area, buf);

        let mut lines: Vec<Line> = vec![];

        for factor in &self.grade.factors {
            let (icon, color) = match factor.status {
                FactorStatus::Pass => ("✓", Color::Green),
                FactorStatus::Warning => ("!", Color::Yellow),
                FactorStatus::Fail => ("✗", Color::Red),
                FactorStatus::NotApplicable => ("-", Color::DarkGray),
            };

            let line = Line::from(vec![
                Span::raw("  "),
                Span::styled(icon, Style::default().fg(color)),
                Span::raw(" "),
                Span::styled(
                    format!("{}: ", factor.name),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::styled(&factor.description, Style::default().fg(Color::Gray)),
                Span::raw(" "),
                Span::styled(
                    format!("({}/{})", factor.points, factor.max_points),
                    Style::default().fg(Color::DarkGray),
                ),
            ]);

            lines.push(line);
        }

        let paragraph = Paragraph::new(lines);
        paragraph.render(inner, buf);
    }
}

fn create_grade_ascii(grade: &str, color: Color) -> Vec<Line<'static>> {
    let style = Style::default().fg(color).add_modifier(Modifier::BOLD);

    vec![
        Line::from(vec![
            Span::styled("╔═══════════════════╗", style),
        ]),
        Line::from(vec![
            Span::styled("║                   ║", style),
        ]),
        Line::from(vec![
            Span::styled("║   Grade: ", style),
            Span::styled(
                format!("{:<8}", grade),
                style.add_modifier(Modifier::BOLD),
            ),
            Span::styled("║", style),
        ]),
        Line::from(vec![
            Span::styled("║                   ║", style),
        ]),
        Line::from(vec![
            Span::styled("╚═══════════════════╝", style),
        ]),
    ]
}

/// Compact grade indicator for status bar or headers
pub struct GradeIndicator<'a> {
    grade: &'a SecurityGrade,
}

impl<'a> GradeIndicator<'a> {
    pub fn new(grade: &'a SecurityGrade) -> Self {
        Self { grade }
    }
}

impl Widget for GradeIndicator<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let color = match self.grade.grade {
            'A' => Color::Green,
            'B' => Color::Cyan,
            'C' => Color::Yellow,
            'D' => Color::Rgb(255, 165, 0),
            _ => Color::Red,
        };

        let text = format!(
            " {} {}% ",
            self.grade.display(),
            self.grade.score
        );

        let span = Span::styled(
            text,
            Style::default()
                .fg(Color::Black)
                .bg(color)
                .add_modifier(Modifier::BOLD),
        );

        buf.set_span(area.x, area.y, &span, area.width);
    }
}
