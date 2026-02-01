//! Configuration module for SSL-Toolkit
//!
//! Handles loading and managing configuration from TOML files.

pub mod messages;
pub mod settings;
pub mod theme;

pub use messages::Messages;
pub use settings::Settings;
pub use theme::Theme;

use crate::utils::ConfigError;
use std::path::Path;

/// Load all configuration from default paths
pub fn load_default_config() -> Result<(Settings, Theme, Messages), ConfigError> {
    let settings = Settings::load_default()?;
    let theme = Theme::load_default()?;
    let messages = Messages::load_default()?;
    Ok((settings, theme, messages))
}

/// Load configuration from a custom directory
pub fn load_config_from_dir<P: AsRef<Path>>(
    dir: P,
) -> Result<(Settings, Theme, Messages), ConfigError> {
    let dir = dir.as_ref();
    let settings = Settings::load_from_file(dir.join("default.toml"))?;
    let theme = Theme::load_from_file(dir.join("theme.toml"))?;
    let messages = Messages::load_from_file(dir.join("messages.toml"))?;
    Ok((settings, theme, messages))
}
