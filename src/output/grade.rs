//! Grade display

use crate::models::Grade;
use console::style;

/// Print a prominent grade box
pub fn print_grade(grade: Grade, score: u32) {
    let grade_str = grade.as_str();
    let label = format!("Grade: {}  Score: {}", grade_str, score);
    let width = label.len() + 6;

    let top = format!("  ╔{}╗", "═".repeat(width));
    let mid = format!("  ║   {}   ║", label);
    let bot = format!("  ╚{}╝", "═".repeat(width));

    println!();
    match grade {
        Grade::APlus | Grade::A | Grade::AMinus => {
            println!("{}", style(&top).green());
            println!("{}", style(&mid).green().bold());
            println!("{}", style(&bot).green());
        }
        Grade::BPlus | Grade::B | Grade::BMinus => {
            println!("{}", style(&top).cyan());
            println!("{}", style(&mid).cyan().bold());
            println!("{}", style(&bot).cyan());
        }
        Grade::CPlus | Grade::C | Grade::CMinus | Grade::D => {
            println!("{}", style(&top).yellow());
            println!("{}", style(&mid).yellow().bold());
            println!("{}", style(&bot).yellow());
        }
        Grade::F => {
            println!("{}", style(&top).red());
            println!("{}", style(&mid).red().bold());
            println!("{}", style(&bot).red());
        }
    }
    println!();
}

/// Print a compact grade line (for non-interactive direct mode)
pub fn print_grade_compact(grade: Grade, score: u32) {
    let grade_str = grade.as_str();
    let styled = match grade {
        Grade::APlus | Grade::A | Grade::AMinus => style(grade_str).green().bold(),
        Grade::BPlus | Grade::B | Grade::BMinus => style(grade_str).cyan().bold(),
        Grade::CPlus | Grade::C | Grade::CMinus => style(grade_str).yellow().bold(),
        Grade::D => style(grade_str).yellow().bold(),
        Grade::F => style(grade_str).red().bold(),
    };

    println!();
    println!("  Grade: {} ({}/100)", styled, score);
}

/// Format a prominent grade box to a string
pub fn format_grade(grade: Grade, score: u32) -> String {
    let grade_str = grade.as_str();
    let label = format!("Grade: {}  Score: {}", grade_str, score);
    let width = label.len() + 6;

    let top = format!("  ╔{}╗", "═".repeat(width));
    let mid = format!("  ║   {}   ║", label);
    let bot = format!("  ╚{}╝", "═".repeat(width));

    let mut out = String::from("\n");
    match grade {
        Grade::APlus | Grade::A | Grade::AMinus => {
            out.push_str(&format!("{}\n", style(&top).green()));
            out.push_str(&format!("{}\n", style(&mid).green().bold()));
            out.push_str(&format!("{}\n", style(&bot).green()));
        }
        Grade::BPlus | Grade::B | Grade::BMinus => {
            out.push_str(&format!("{}\n", style(&top).cyan()));
            out.push_str(&format!("{}\n", style(&mid).cyan().bold()));
            out.push_str(&format!("{}\n", style(&bot).cyan()));
        }
        Grade::CPlus | Grade::C | Grade::CMinus | Grade::D => {
            out.push_str(&format!("{}\n", style(&top).yellow()));
            out.push_str(&format!("{}\n", style(&mid).yellow().bold()));
            out.push_str(&format!("{}\n", style(&bot).yellow()));
        }
        Grade::F => {
            out.push_str(&format!("{}\n", style(&top).red()));
            out.push_str(&format!("{}\n", style(&mid).red().bold()));
            out.push_str(&format!("{}\n", style(&bot).red()));
        }
    }
    out.push('\n');
    out
}

/// Print just the grade letter (for quiet mode)
pub fn print_grade_quiet(grade: Grade) {
    println!("{}", grade.as_str());
}
