//! Main menu widget

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, HighlightSpacing, List, ListItem, ListState, StatefulWidget, Widget},
};

/// Menu items for the main menu
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MenuItem {
    CheckDomain,
    BatchCheck,
    WatchDomain,
    CompareCertificates,
    SearchCtLogs,
    GenerateTlsa,
    Settings,
    Exit,
}

impl MenuItem {
    pub fn all() -> Vec<MenuItem> {
        vec![
            MenuItem::CheckDomain,
            MenuItem::BatchCheck,
            MenuItem::WatchDomain,
            MenuItem::CompareCertificates,
            MenuItem::SearchCtLogs,
            MenuItem::GenerateTlsa,
            MenuItem::Settings,
            MenuItem::Exit,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            MenuItem::CheckDomain => "Check SSL certificate for a domain",
            MenuItem::BatchCheck => "Batch check multiple domains",
            MenuItem::WatchDomain => "Watch a domain for certificate changes",
            MenuItem::CompareCertificates => "Compare two certificates",
            MenuItem::SearchCtLogs => "Search Certificate Transparency logs",
            MenuItem::GenerateTlsa => "Generate TLSA/DANE record",
            MenuItem::Settings => "Settings",
            MenuItem::Exit => "Exit",
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            MenuItem::CheckDomain => "🔒",
            MenuItem::BatchCheck => "📋",
            MenuItem::WatchDomain => "👁",
            MenuItem::CompareCertificates => "⚖",
            MenuItem::SearchCtLogs => "🔍",
            MenuItem::GenerateTlsa => "📝",
            MenuItem::Settings => "⚙",
            MenuItem::Exit => "🚪",
        }
    }
}

/// Menu widget state
pub struct MenuState {
    pub items: Vec<MenuItem>,
    pub list_state: ListState,
}

impl Default for MenuState {
    fn default() -> Self {
        let mut list_state = ListState::default();
        list_state.select(Some(0));
        Self {
            items: MenuItem::all(),
            list_state,
        }
    }
}

impl MenuState {
    pub fn next(&mut self) {
        let i = match self.list_state.selected() {
            Some(i) => {
                if i >= self.items.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.list_state.select(Some(i));
    }

    pub fn previous(&mut self) {
        let i = match self.list_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.items.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.list_state.select(Some(i));
    }

    pub fn selected(&self) -> Option<MenuItem> {
        self.list_state
            .selected()
            .and_then(|i| self.items.get(i).copied())
    }
}

/// Menu widget
pub struct MenuWidget<'a> {
    block: Option<Block<'a>>,
}

impl<'a> MenuWidget<'a> {
    pub fn new() -> Self {
        Self { block: None }
    }

    pub fn block(mut self, block: Block<'a>) -> Self {
        self.block = Some(block);
        self
    }
}

impl<'a> StatefulWidget for MenuWidget<'a> {
    type State = MenuState;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        let items: Vec<ListItem> = state
            .items
            .iter()
            .map(|item| {
                let content = Line::from(vec![
                    Span::raw("  "),
                    Span::styled(item.icon(), Style::default()),
                    Span::raw("  "),
                    Span::styled(
                        item.label(),
                        Style::default().fg(Color::White),
                    ),
                ]);
                ListItem::new(content)
            })
            .collect();

        let list = List::new(items)
            .highlight_style(
                Style::default()
                    .bg(Color::Cyan)
                    .fg(Color::Black)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ")
            .highlight_spacing(HighlightSpacing::Always);

        let list = if let Some(block) = self.block {
            list.block(block)
        } else {
            list.block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan))
                    .title(" Main Menu "),
            )
        };

        StatefulWidget::render(list, area, buf, &mut state.list_state);
    }
}

impl<'a> Default for MenuWidget<'a> {
    fn default() -> Self {
        Self::new()
    }
}
