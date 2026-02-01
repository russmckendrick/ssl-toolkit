//! Theme configuration for CLI display
//!
//! Defines icons, colors, and box drawing characters.

use crate::utils::ConfigError;
use console::Style;
use serde::Deserialize;
use std::path::Path;

/// Status icons
#[derive(Debug, Clone, Deserialize)]
pub struct Icons {
    pub pass: String,
    pub fail: String,
    pub warning: String,
    pub info: String,
    pub critical: String,
    pub cert_leaf: String,
    pub cert_intermediate: String,
    pub cert_root: String,
    pub arrow_right: String,
    pub bullet: String,
    pub spinner: Vec<String>,
    #[serde(default = "Icons::default_nav_left")]
    pub nav_left: String,
    #[serde(default = "Icons::default_nav_right")]
    pub nav_right: String,
    #[serde(default = "Icons::default_step_complete")]
    pub step_complete: String,
    #[serde(default = "Icons::default_step_current")]
    pub step_current: String,
    #[serde(default = "Icons::default_step_pending")]
    pub step_pending: String,
}

impl Icons {
    fn default_nav_left() -> String {
        "←".to_string()
    }
    fn default_nav_right() -> String {
        "→".to_string()
    }
    fn default_step_complete() -> String {
        "●".to_string()
    }
    fn default_step_current() -> String {
        "◉".to_string()
    }
    fn default_step_pending() -> String {
        "○".to_string()
    }
}

impl Default for Icons {
    fn default() -> Self {
        Self {
            pass: "✓".to_string(),
            fail: "✗".to_string(),
            warning: "⚠".to_string(),
            info: "ℹ".to_string(),
            critical: "⛔".to_string(),
            cert_leaf: "●".to_string(),
            cert_intermediate: "+".to_string(),
            cert_root: "■".to_string(),
            arrow_right: "→".to_string(),
            bullet: "•".to_string(),
            spinner: vec![
                "⠋".to_string(),
                "⠙".to_string(),
                "⠹".to_string(),
                "⠸".to_string(),
                "⠼".to_string(),
                "⠴".to_string(),
                "⠦".to_string(),
                "⠧".to_string(),
                "⠇".to_string(),
                "⠏".to_string(),
            ],
            nav_left: "←".to_string(),
            nav_right: "→".to_string(),
            step_complete: "●".to_string(),
            step_current: "◉".to_string(),
            step_pending: "○".to_string(),
        }
    }
}

/// Box drawing characters
#[derive(Debug, Clone, Deserialize)]
pub struct BoxChars {
    pub top_left: char,
    pub top_right: char,
    pub bottom_left: char,
    pub bottom_right: char,
    pub horizontal: char,
    pub vertical: char,
    pub t_left: char,
    pub t_right: char,
    pub t_top: char,
    pub t_bottom: char,
    pub cross: char,
}

impl Default for BoxChars {
    fn default() -> Self {
        Self {
            top_left: '┌',
            top_right: '┐',
            bottom_left: '└',
            bottom_right: '┘',
            horizontal: '─',
            vertical: '│',
            t_left: '├',
            t_right: '┤',
            t_top: '┬',
            t_bottom: '┴',
            cross: '┼',
        }
    }
}

/// Double-line box characters for outer borders
#[derive(Debug, Clone, Deserialize)]
pub struct DoubleBoxChars {
    pub top_left: char,
    pub top_right: char,
    pub bottom_left: char,
    pub bottom_right: char,
    pub horizontal: char,
    pub vertical: char,
}

impl Default for DoubleBoxChars {
    fn default() -> Self {
        Self {
            top_left: '╔',
            top_right: '╗',
            bottom_left: '╚',
            bottom_right: '╝',
            horizontal: '═',
            vertical: '║',
        }
    }
}

/// Color scheme (stored as hex strings, converted to console styles)
#[derive(Debug, Clone, Deserialize)]
pub struct Colors {
    pub pass: String,
    pub fail: String,
    pub warning: String,
    pub info: String,
    pub primary: String,
    pub secondary: String,
    pub background: String,
    pub foreground: String,
    pub border: String,
    pub highlight: String,
    #[serde(default = "Colors::default_key_background")]
    pub key_background: String,
    #[serde(default = "Colors::default_key_foreground")]
    pub key_foreground: String,
    #[serde(default = "Colors::default_table_header_bg")]
    pub table_header_bg: String,
    #[serde(default = "Colors::default_grade_a")]
    pub grade_a: String,
    #[serde(default = "Colors::default_grade_b")]
    pub grade_b: String,
    #[serde(default = "Colors::default_grade_c")]
    pub grade_c: String,
    #[serde(default = "Colors::default_grade_f")]
    pub grade_f: String,
    #[serde(default = "Colors::default_bar_filled")]
    pub bar_filled: String,
    #[serde(default = "Colors::default_bar_empty")]
    pub bar_empty: String,
}

impl Colors {
    fn default_key_background() -> String {
        "#374151".to_string()
    }
    fn default_key_foreground() -> String {
        "#F9FAFB".to_string()
    }
    fn default_table_header_bg() -> String {
        "#374151".to_string()
    }
    fn default_grade_a() -> String {
        "#10B981".to_string()
    }
    fn default_grade_b() -> String {
        "#3B82F6".to_string()
    }
    fn default_grade_c() -> String {
        "#F59E0B".to_string()
    }
    fn default_grade_f() -> String {
        "#EF4444".to_string()
    }
    fn default_bar_filled() -> String {
        "#10B981".to_string()
    }
    fn default_bar_empty() -> String {
        "#374151".to_string()
    }
}

impl Default for Colors {
    fn default() -> Self {
        Self {
            pass: "#10B981".to_string(),
            fail: "#EF4444".to_string(),
            warning: "#F59E0B".to_string(),
            info: "#3B82F6".to_string(),
            primary: "#7C3AED".to_string(),
            secondary: "#6B7280".to_string(),
            background: "#1F2937".to_string(),
            foreground: "#F9FAFB".to_string(),
            border: "#374151".to_string(),
            highlight: "#60A5FA".to_string(),
            key_background: Self::default_key_background(),
            key_foreground: Self::default_key_foreground(),
            table_header_bg: Self::default_table_header_bg(),
            grade_a: Self::default_grade_a(),
            grade_b: Self::default_grade_b(),
            grade_c: Self::default_grade_c(),
            grade_f: Self::default_grade_f(),
            bar_filled: Self::default_bar_filled(),
            bar_empty: Self::default_bar_empty(),
        }
    }
}

impl Colors {
    /// Parse a hex color string to RGB components
    pub fn hex_to_rgb(hex: &str) -> (u8, u8, u8) {
        let hex = hex.trim_start_matches('#');
        if hex.len() != 6 {
            return (255, 255, 255);
        }
        let r = u8::from_str_radix(&hex[0..2], 16).unwrap_or(255);
        let g = u8::from_str_radix(&hex[2..4], 16).unwrap_or(255);
        let b = u8::from_str_radix(&hex[4..6], 16).unwrap_or(255);
        (r, g, b)
    }

    /// Create a console::Style with the given hex color as foreground
    pub fn style_from_hex(hex: &str) -> Style {
        let (r, g, b) = Self::hex_to_rgb(hex);
        Style::new().color256(
            // Map RGB to closest 256-color
            16 + (36 * (r as u16 * 5 / 255) + 6 * (g as u16 * 5 / 255) + (b as u16 * 5 / 255))
                as u8,
        )
    }

    /// Create a console::Style for pass status
    pub fn pass_style(&self) -> Style {
        Style::new().green()
    }

    /// Create a console::Style for fail status
    pub fn fail_style(&self) -> Style {
        Style::new().red()
    }

    /// Create a console::Style for warning status
    pub fn warning_style(&self) -> Style {
        Style::new().yellow()
    }

    /// Create a console::Style for info status
    pub fn info_style(&self) -> Style {
        Style::new().cyan()
    }

    /// Create a console::Style for primary text
    pub fn primary_style(&self) -> Style {
        Style::new().magenta().bold()
    }

    /// Create a console::Style for secondary/dim text
    pub fn secondary_style(&self) -> Style {
        Style::new().dim()
    }
}

/// Visual characters for progress bars, badges, etc.
#[derive(Debug, Clone, Deserialize)]
pub struct Visual {
    #[serde(default = "Visual::default_bar_filled")]
    pub bar_filled: String,
    #[serde(default = "Visual::default_bar_partial")]
    pub bar_partial: String,
    #[serde(default = "Visual::default_bar_empty")]
    pub bar_empty: String,
    #[serde(default = "Visual::default_dot_filled")]
    pub dot_filled: String,
    #[serde(default = "Visual::default_dot_empty")]
    pub dot_empty: String,
    #[serde(default = "Visual::default_badge_left")]
    pub badge_left: String,
    #[serde(default = "Visual::default_badge_right")]
    pub badge_right: String,
    #[serde(default = "Visual::default_expand_open")]
    pub expand_open: String,
    #[serde(default = "Visual::default_expand_closed")]
    pub expand_closed: String,
}

impl Visual {
    fn default_bar_filled() -> String {
        "█".to_string()
    }
    fn default_bar_partial() -> String {
        "░".to_string()
    }
    fn default_bar_empty() -> String {
        "░".to_string()
    }
    fn default_dot_filled() -> String {
        "●".to_string()
    }
    fn default_dot_empty() -> String {
        "○".to_string()
    }
    fn default_badge_left() -> String {
        "[".to_string()
    }
    fn default_badge_right() -> String {
        "]".to_string()
    }
    fn default_expand_open() -> String {
        "▼".to_string()
    }
    fn default_expand_closed() -> String {
        "▶".to_string()
    }
}

impl Default for Visual {
    fn default() -> Self {
        Self {
            bar_filled: Self::default_bar_filled(),
            bar_partial: Self::default_bar_partial(),
            bar_empty: Self::default_bar_empty(),
            dot_filled: Self::default_dot_filled(),
            dot_empty: Self::default_dot_empty(),
            badge_left: Self::default_badge_left(),
            badge_right: Self::default_badge_right(),
            expand_open: Self::default_expand_open(),
            expand_closed: Self::default_expand_closed(),
        }
    }
}

/// Complete theme configuration
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Theme {
    #[serde(default)]
    pub icons: Icons,
    #[serde(default)]
    pub box_chars: BoxChars,
    #[serde(default)]
    pub double_box: DoubleBoxChars,
    #[serde(default)]
    pub colors: Colors,
    #[serde(default)]
    pub visual: Visual,
}

impl Theme {
    /// Load theme from the default config file
    pub fn load_default() -> Result<Self, ConfigError> {
        let config_path = Path::new("config/theme.toml");
        if config_path.exists() {
            Self::load_from_file(config_path)
        } else {
            Ok(Self::default())
        }
    }

    /// Load theme from a specific file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path).map_err(|_| ConfigError::FileNotFound {
            path: path.display().to_string(),
        })?;

        toml::from_str(&content).map_err(|e| ConfigError::ParseError {
            message: e.to_string(),
        })
    }
}
