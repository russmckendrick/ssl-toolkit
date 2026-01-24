//! Results display widget

use crate::certificate::{CertificateChain, CertificateInfo, SecurityGrade, TrustStatus};
use crate::dns::DnsInfo;
use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{
        Block, Borders, List, ListItem, ListState, Paragraph, Scrollbar, ScrollbarOrientation,
        ScrollbarState, StatefulWidget, Tabs, Widget, Wrap,
    },
};

/// Result sections
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum ResultSection {
    #[default]
    Grade,
    Certificate,
    Chain,
    Dns,
    Sans,
}

impl ResultSection {
    pub fn all() -> Vec<ResultSection> {
        vec![
            ResultSection::Grade,
            ResultSection::Certificate,
            ResultSection::Chain,
            ResultSection::Dns,
            ResultSection::Sans,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            ResultSection::Grade => "Grade",
            ResultSection::Certificate => "Certificate",
            ResultSection::Chain => "Chain",
            ResultSection::Dns => "DNS",
            ResultSection::Sans => "SANs",
        }
    }
}

/// Which panel has focus in results view
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum ResultsFocus {
    #[default]
    Sections,  // Left panel - section list
    Content,   // Right panel - scrollable content
}

/// Results widget state
pub struct ResultsState {
    pub section: ResultSection,
    pub section_index: usize,
    pub scroll_offset: usize,
    pub content_height: usize,
    pub list_state: ListState,
    pub focus: ResultsFocus,
}

impl Default for ResultsState {
    fn default() -> Self {
        Self {
            section: ResultSection::Grade,
            section_index: 0,
            scroll_offset: 0,
            content_height: 0,
            list_state: ListState::default(),
            focus: ResultsFocus::Sections,
        }
    }
}

impl ResultsState {
    /// Switch focus to the other panel
    pub fn toggle_focus(&mut self) {
        self.focus = match self.focus {
            ResultsFocus::Sections => ResultsFocus::Content,
            ResultsFocus::Content => ResultsFocus::Sections,
        };
    }

    /// Move focus left (to sections)
    pub fn focus_left(&mut self) {
        self.focus = ResultsFocus::Sections;
    }

    /// Move focus right (to content)
    pub fn focus_right(&mut self) {
        self.focus = ResultsFocus::Content;
    }
}

impl ResultsState {
    pub fn next_section(&mut self) {
        let sections = ResultSection::all();
        self.section_index = (self.section_index + 1) % sections.len();
        self.section = sections[self.section_index];
        self.scroll_offset = 0;
    }

    pub fn previous_section(&mut self) {
        let sections = ResultSection::all();
        self.section_index = if self.section_index == 0 {
            sections.len() - 1
        } else {
            self.section_index - 1
        };
        self.section = sections[self.section_index];
        self.scroll_offset = 0;
    }

    pub fn scroll_up(&mut self, amount: usize) {
        self.scroll_offset = self.scroll_offset.saturating_sub(amount);
    }

    pub fn scroll_down(&mut self, amount: usize, max: usize) {
        self.scroll_offset = (self.scroll_offset + amount).min(max.saturating_sub(1));
    }
}

/// Results display data
#[derive(Debug, Clone)]
pub struct ResultsData {
    pub domain: String,
    pub port: u16,
    pub grade: Option<SecurityGrade>,
    pub chain: Option<CertificateChain>,
    pub dns: Option<DnsInfo>,
}

impl ResultsData {
    pub fn new(domain: &str, port: u16) -> Self {
        Self {
            domain: domain.to_string(),
            port,
            grade: None,
            chain: None,
            dns: None,
        }
    }
}

/// Results widget
pub struct ResultsWidget<'a> {
    data: &'a ResultsData,
}

impl<'a> ResultsWidget<'a> {
    pub fn new(data: &'a ResultsData) -> Self {
        Self { data }
    }
}

impl<'a> StatefulWidget for ResultsWidget<'a> {
    type State = ResultsState;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        // Main layout: tabs on left, content on right
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(16), Constraint::Min(40)])
            .split(area);

        // Render section tabs (as vertical list)
        self.render_section_list(chunks[0], buf, state);

        // Render current section content
        self.render_section_content(chunks[1], buf, state);
    }
}

impl<'a> ResultsWidget<'a> {
    fn render_section_list(&self, area: Rect, buf: &mut Buffer, state: &ResultsState) {
        let is_focused = state.focus == ResultsFocus::Sections;

        let items: Vec<ListItem> = ResultSection::all()
            .iter()
            .enumerate()
            .map(|(i, section)| {
                let style = if i == state.section_index {
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Gray)
                };
                let prefix = if i == state.section_index { "> " } else { "  " };
                ListItem::new(format!("{}{}", prefix, section.label())).style(style)
            })
            .collect();

        // Highlight border when focused
        let border_color = if is_focused { Color::Cyan } else { Color::DarkGray };
        let title_style = if is_focused {
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        let list = List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color))
                .title(" Sections ")
                .title_style(title_style),
        );

        Widget::render(list, area, buf);
    }

    fn render_section_content(&self, area: Rect, buf: &mut Buffer, state: &mut ResultsState) {
        let is_focused = state.focus == ResultsFocus::Content;

        // Highlight border when focused
        let border_color = if is_focused { Color::Cyan } else { Color::DarkGray };
        let title_style = if is_focused {
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color))
            .title(format!(" {} ", state.section.label()))
            .title_style(title_style);

        let inner = block.inner(area);
        block.render(area, buf);

        let content = match state.section {
            ResultSection::Grade => self.render_grade_content(state),
            ResultSection::Certificate => self.render_certificate_content(state),
            ResultSection::Chain => self.render_chain_content(state),
            ResultSection::Dns => self.render_dns_content(state),
            ResultSection::Sans => self.render_sans_content(state),
        };

        // Store content height for scrolling
        state.content_height = content.lines.len();

        let paragraph = Paragraph::new(content)
            .wrap(Wrap { trim: false })
            .scroll((state.scroll_offset as u16, 0));

        paragraph.render(inner, buf);

        // Render scrollbar if needed
        if state.content_height > inner.height as usize {
            let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("↑"))
                .end_symbol(Some("↓"));

            let mut scrollbar_state = ScrollbarState::new(state.content_height)
                .position(state.scroll_offset);

            scrollbar.render(
                inner,
                buf,
                &mut scrollbar_state,
            );
        }
    }

    fn render_grade_content(&self, _state: &ResultsState) -> Text<'static> {
        let mut lines = vec![];

        if let Some(ref grade) = self.data.grade {
            // Grade display
            let grade_color = match grade.grade {
                'A' => Color::Green,
                'B' => Color::Cyan,
                'C' => Color::Yellow,
                'D' => Color::Rgb(255, 165, 0),
                _ => Color::Red,
            };

            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled(
                    "  ╔═══════════════════╗",
                    Style::default().fg(grade_color),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::styled(
                    format!("  ║   Grade: {:<8} ║", grade.display()),
                    Style::default().fg(grade_color).add_modifier(Modifier::BOLD),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::styled(
                    format!("  ║   Score: {:>3}%     ║", grade.score),
                    Style::default().fg(grade_color),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::styled(
                    "  ╚═══════════════════╝",
                    Style::default().fg(grade_color),
                ),
            ]));
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled(
                    "  Grade Factors:",
                    Style::default().add_modifier(Modifier::BOLD),
                ),
            ]));
            lines.push(Line::from(""));

            for factor in &grade.factors {
                let (icon, color) = match factor.status {
                    crate::certificate::security::FactorStatus::Pass => ("✓", Color::Green),
                    crate::certificate::security::FactorStatus::Warning => ("!", Color::Yellow),
                    crate::certificate::security::FactorStatus::Fail => ("✗", Color::Red),
                    crate::certificate::security::FactorStatus::NotApplicable => ("-", Color::DarkGray),
                };

                lines.push(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(icon, Style::default().fg(color)),
                    Span::raw(" "),
                    Span::styled(
                        format!("{}: ", factor.name),
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        factor.description.clone(),
                        Style::default().fg(Color::Gray),
                    ),
                    Span::styled(
                        format!(" ({}/{})", factor.points, factor.max_points),
                        Style::default().fg(Color::DarkGray),
                    ),
                ]));
            }
        } else {
            lines.push(Line::from("  No grade data available"));
        }

        Text::from(lines)
    }

    fn render_certificate_content(&self, _state: &ResultsState) -> Text<'static> {
        let mut lines = vec![];

        if let Some(ref chain) = self.data.chain {
            if let Some(cert) = chain.leaf() {
                lines.push(Line::from(""));
                self.add_field(&mut lines, "Subject", &cert.subject.common_name.clone().unwrap_or_default());
                self.add_field(&mut lines, "Issuer", &cert.issuer.common_name.clone().unwrap_or_default());
                lines.push(Line::from(""));
                self.add_field(
                    &mut lines,
                    "Valid From",
                    &cert.not_before.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                );
                self.add_field(
                    &mut lines,
                    "Valid Until",
                    &cert.not_after.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                );
                self.add_expiry_field(&mut lines, cert.days_until_expiry);
                lines.push(Line::from(""));
                self.add_field(&mut lines, "Serial Number", &cert.serial_number);
                self.add_field(&mut lines, "Key Algorithm", &cert.key_algorithm.to_string());
                self.add_field(&mut lines, "Signature", &cert.signature_algorithm);
                lines.push(Line::from(""));
                self.add_trust_field(&mut lines, &cert.trust_status);
            }
        } else {
            lines.push(Line::from("  No certificate data available"));
        }

        Text::from(lines)
    }

    fn render_chain_content(&self, _state: &ResultsState) -> Text<'static> {
        let mut lines = vec![];

        if let Some(ref chain) = self.data.chain {
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("  ℹ ", Style::default().fg(Color::Blue)),
                Span::raw(format!("Chain length: {}", chain.chain_length)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("  ℹ ", Style::default().fg(Color::Blue)),
                Span::raw("Complete: "),
                if chain.is_complete {
                    Span::styled("Yes", Style::default().fg(Color::Green))
                } else {
                    Span::styled("No", Style::default().fg(Color::Red))
                },
            ]));
            lines.push(Line::from(vec![
                Span::styled("  ℹ ", Style::default().fg(Color::Blue)),
                Span::raw("Root in trust store: "),
                if chain.root_in_store {
                    Span::styled("Yes", Style::default().fg(Color::Green))
                } else {
                    Span::styled("Unknown", Style::default().fg(Color::Yellow))
                },
            ]));
            lines.push(Line::from(""));

            for (i, cert) in chain.certificates.iter().enumerate() {
                let prefix = if i == 0 {
                    "└─ [Leaf]"
                } else if i == chain.certificates.len() - 1 {
                    "   └─ [Root]"
                } else {
                    "   ├─ [Intermediate]"
                };

                let indent = "   ".repeat(i);
                let name = cert.subject.common_name.clone().unwrap_or_default();

                lines.push(Line::from(vec![
                    Span::raw(format!("  {}", indent)),
                    Span::styled(prefix, Style::default().fg(Color::Cyan)),
                    Span::raw(" "),
                    Span::styled(name, Style::default().add_modifier(Modifier::BOLD)),
                ]));
            }
        } else {
            lines.push(Line::from("  No chain data available"));
        }

        Text::from(lines)
    }

    fn render_dns_content(&self, _state: &ResultsState) -> Text<'static> {
        let mut lines = vec![];

        if let Some(ref dns) = self.data.dns {
            lines.push(Line::from(""));

            if !dns.ipv4_addresses.is_empty() {
                lines.push(Line::from(vec![
                    Span::styled("  IPv4 Addresses:", Style::default().add_modifier(Modifier::BOLD)),
                ]));
                for ip in &dns.ipv4_addresses {
                    lines.push(Line::from(vec![
                        Span::styled("    • ", Style::default().fg(Color::Cyan)),
                        Span::raw(ip.to_string()),
                    ]));
                }
                lines.push(Line::from(""));
            }

            if !dns.ipv6_addresses.is_empty() {
                lines.push(Line::from(vec![
                    Span::styled("  IPv6 Addresses:", Style::default().add_modifier(Modifier::BOLD)),
                ]));
                for ip in &dns.ipv6_addresses {
                    lines.push(Line::from(vec![
                        Span::styled("    • ", Style::default().fg(Color::Cyan)),
                        Span::raw(ip.to_string()),
                    ]));
                }
                lines.push(Line::from(""));
            }

            if !dns.nameservers.is_empty() {
                lines.push(Line::from(vec![
                    Span::styled("  Nameservers:", Style::default().add_modifier(Modifier::BOLD)),
                ]));
                for ns in &dns.nameservers {
                    lines.push(Line::from(vec![
                        Span::styled("    • ", Style::default().fg(Color::Cyan)),
                        Span::raw(ns.clone()),
                    ]));
                }
                lines.push(Line::from(""));
            }

            lines.push(Line::from(vec![
                Span::styled("  ℹ ", Style::default().fg(Color::Blue)),
                Span::raw("DNSSEC: "),
                if dns.dnssec_enabled {
                    Span::styled("Enabled", Style::default().fg(Color::Green))
                } else {
                    Span::styled("Not detected", Style::default().fg(Color::Yellow))
                },
            ]));

            if !dns.caa_records.is_empty() {
                lines.push(Line::from(""));
                lines.push(Line::from(vec![
                    Span::styled("  CAA Records:", Style::default().add_modifier(Modifier::BOLD)),
                ]));
                for caa in &dns.caa_records {
                    lines.push(Line::from(vec![
                        Span::styled("    • ", Style::default().fg(Color::Cyan)),
                        Span::raw(format!("{} {} \"{}\"", caa.flags, caa.tag, caa.value)),
                    ]));
                }
            }
        } else {
            lines.push(Line::from("  No DNS data available"));
        }

        Text::from(lines)
    }

    fn render_sans_content(&self, _state: &ResultsState) -> Text<'static> {
        let mut lines = vec![];

        if let Some(ref chain) = self.data.chain {
            if let Some(cert) = chain.leaf() {
                lines.push(Line::from(""));
                if cert.subject_alt_names.is_empty() {
                    lines.push(Line::from("  No Subject Alternative Names"));
                } else {
                    lines.push(Line::from(vec![
                        Span::styled(
                            format!("  {} SANs found:", cert.subject_alt_names.len()),
                            Style::default().add_modifier(Modifier::BOLD),
                        ),
                    ]));
                    lines.push(Line::from(""));
                    for san in &cert.subject_alt_names {
                        lines.push(Line::from(vec![
                            Span::styled("    • ", Style::default().fg(Color::Cyan)),
                            Span::raw(san.clone()),
                        ]));
                    }
                }
            }
        } else {
            lines.push(Line::from("  No certificate data available"));
        }

        Text::from(lines)
    }

    fn add_field(&self, lines: &mut Vec<Line<'static>>, label: &str, value: &str) {
        lines.push(Line::from(vec![
            Span::styled(
                format!("  {}: ", label),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw(value.to_string()),
        ]));
    }

    fn add_expiry_field(&self, lines: &mut Vec<Line<'static>>, days: i64) {
        let (text, color) = if days < 0 {
            (format!("Expired {} days ago", days.abs()), Color::Red)
        } else if days == 0 {
            ("Expires today!".to_string(), Color::Red)
        } else if days <= 7 {
            (format!("{} days (critical)", days), Color::Red)
        } else if days <= 30 {
            (format!("{} days (warning)", days), Color::Yellow)
        } else {
            (format!("{} days", days), Color::Green)
        };

        lines.push(Line::from(vec![
            Span::styled("  Days Until Expiry: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(text, Style::default().fg(color)),
        ]));
    }

    fn add_trust_field(&self, lines: &mut Vec<Line<'static>>, status: &TrustStatus) {
        let (text, color) = match status {
            TrustStatus::Trusted => ("✓ Trusted", Color::Green),
            TrustStatus::Untrusted => ("✗ Untrusted", Color::Red),
            TrustStatus::SelfSigned => ("! Self-Signed", Color::Yellow),
            TrustStatus::Expired => ("✗ Expired", Color::Red),
            TrustStatus::NotYetValid => ("✗ Not Yet Valid", Color::Red),
            TrustStatus::Revoked => ("✗ Revoked", Color::Red),
            TrustStatus::Unknown => ("? Unknown", Color::Gray),
        };

        lines.push(Line::from(vec![
            Span::styled("  Trust Status: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(text, Style::default().fg(color)),
        ]));
    }
}
