//! TUI Widgets

pub mod grade;
pub mod input;
pub mod menu;
pub mod results;
pub mod save_menu;
pub mod status;

pub use grade::GradeWidget;
pub use input::InputWidget;
pub use menu::MenuWidget;
pub use results::ResultsWidget;
pub use save_menu::{SaveMenuState, SaveMenuWidget, SaveOption, SavePathState, SavingState};
pub use status::StatusBar;
