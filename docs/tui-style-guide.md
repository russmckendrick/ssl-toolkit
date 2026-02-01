# Output Style Guide

This document defines the visual and interaction standards for the SSL Toolkit CLI output and pager view.

## Box Drawing Characters

### Single-Line Borders (Standard Content)

Used for primary content boxes and result containers with rounded corners.

```
╭─────────────────────────────────────╮
│  Content area                       │
│                                     │
╰─────────────────────────────────────╯
```

| Character | Unicode | Name | Usage |
|-----------|---------|------|-------|
| `╭` | U+256D | Rounded top-left | Start of box |
| `╮` | U+256E | Rounded top-right | End of top border |
| `╰` | U+2570 | Rounded bottom-left | Start of bottom border |
| `╯` | U+2571 | Rounded bottom-right | End of box |
| `─` | U+2500 | Horizontal line | Top/bottom borders |
| `│` | U+2502 | Vertical line | Side borders |
| `├` | U+251C | T-junction right | Nested section start |
| `┤` | U+2524 | T-junction left | Nested section end |
| `┬` | U+252C | T-junction down | Column separator header |
| `┴` | U+2534 | T-junction up | Column separator footer |
| `┼` | U+253C | Cross | Table intersection |

### Double-Line Borders (Section Headers & Emphasis)

Used for major section dividers and the overall grade display. Also uses rounded corners.

```
╭═══════════════════════════════════════╮
║           OVERALL GRADE: A            ║
╰═══════════════════════════════════════╯
```

| Character | Unicode | Name | Usage |
|-----------|---------|------|-------|
| `╭` | U+256D | Rounded top-left | Grade box, emphasis |
| `╮` | U+256E | Rounded top-right | Grade box, emphasis |
| `╰` | U+2570 | Rounded bottom-left | Grade box, emphasis |
| `╯` | U+2571 | Rounded bottom-right | Grade box, emphasis |
| `═` | U+2550 | Double horizontal | Section headers |
| `║` | U+2551 | Double vertical | Grade box sides |

### Section Dividers

Section headers use double-line characters for visual distinction:

```
════════════════════════════════════════════════════════════════════════════
 DNS RESOLUTION
════════════════════════════════════════════════════════════════════════════
```

---

## Pager Layout

The application uses a ratatui-based pager for displaying results. The pager has two areas:

### Layout Structure

```
╭────────────────────────────────────────────────────────╮
│                                                        │
│  [Scrollable Content Area]                             │
│                                                        │
│  Results are rendered as formatted text with ANSI      │
│  colors and box drawing characters.                    │
│                                                        │
├────────────────────────────────────────────────────────┤
│  ↑↓/jk: Scroll │ s: Save │ n: New Check │ q: Quit    │  <- Status Bar
╰────────────────────────────────────────────────────────╯
```

### Interactive Prompts

Before the pager, the application uses `inquire` for sequential prompts:
1. Domain input (if not provided via CLI)
2. IP selection (multi-select from DNS results)
3. Port input (if not provided via CLI)

These are standard terminal prompts, not a TUI.

---

## Nesting Rules

### Standard Inset: 3 Characters

All nested boxes must be inset by exactly **3 characters** from their parent container. This includes:
- 1 space after parent's left border
- The nested box border
- 1 space before parent's right border

```
╭─ Outer Box ──────────────────────────────────────────────────────────────╮
│                                                                          │
│  ✓ Summary line here                                                     │
│                                                                          │
│  ╭─ Additional Details ───────────────────────────────────────────────╮  │
│  │                                                                    │  │
│  │  Content inside nested box                                         │  │
│  │                                                                    │  │
│  ╰────────────────────────────────────────────────────────────────────╯  │
│                                                                          │
╰──────────────────────────────────────────────────────────────────────────╯
```

### Inner Content Padding

Within each box:
- **2 spaces** padding from left border to content
- **2 spaces** padding from content to right border

```
│  Content starts here with 2-space padding                               │
```

### Nested Box Titles

Nested box titles follow the format `╭─ Title ─` with dashes filling to the right:

```
╭─ Additional Details ───────────────────────────────────────────────────╮
╭─ Test Steps ───────────────────────────────────────────────────────────╮
╭─ Recommendations ──────────────────────────────────────────────────────╮
╭─ Certificate Chain ────────────────────────────────────────────────────╮
```

---

## Color Conventions

All colors are defined in `config/theme.toml` using the Tokyo Night Storm palette.

### Status Colors

| Status | Color | Hex | Usage |
|--------|-------|-----|-------|
| Pass | Green | `#9ece6a` | Successful checks, valid certificates |
| Fail | Red | `#f7768e` | Failed checks, errors, expired certs |
| Warning | Orange | `#e0af68` | Non-critical issues, deprecation notices |
| Info | Cyan | `#7dcfff` | Neutral information, hints |

### UI Colors

| Element | Color | Hex | Usage |
|---------|-------|-----|-------|
| Primary | Blue | `#7aa2f7` | Borders, highlights, accents |
| Secondary | Lavender | `#a9b1d6` | Secondary text |
| Foreground | Light | `#c0caf5` | Main text |
| Background | Storm Blue | `#24283b` | Background |
| Border | Muted Blue | `#565f89` | Box borders |
| Highlight | Purple | `#bb9af7` | Highlighted elements |

### Grade Colors

| Grade | Color |
|-------|-------|
| A+, A, A- | Green (`#9ece6a`) |
| B+, B, B- | Blue (`#7aa2f7`) |
| C+, C, C- | Orange (`#e0af68`) |
| D | Orange (`#e0af68`) |
| F | Red (`#f7768e`) |

---

## Icon Usage

Icons are defined in `config/theme.toml` and provide visual status indicators.

### Status Icons

| Icon | Meaning | Usage |
|------|---------|-------|
| `✓` | Pass | Successful check, valid item |
| `✗` | Fail | Failed check, invalid item |
| `!` | Warning | Non-critical issue |
| `i` | Info | Informational message |
| `X` | Critical | Critical error, immediate action required |

### Certificate Icons

| Icon | Meaning | Usage |
|------|---------|-------|
| `📄` | Leaf Certificate | End-entity certificate |
| `⛓` | Intermediate Certificate | CA intermediate |
| `🔒` | Root Certificate | Trusted root CA |

### Spinner Animation

The spinner cycles through these frames at 80ms intervals:

```
⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏
```

### Visual Indicators

| Element | Default | Config Key | Usage |
|---------|---------|------------|-------|
| Bar Filled | `━` | `visual.bar_filled` | Progress bar filled portion |
| Bar Partial | `╸` | `visual.bar_partial` | Progress bar partial/fractional portion |
| Bar Empty | `─` | `visual.bar_empty` | Progress bar empty background |
| Dot Filled | `●` | `visual.dot_filled` | Step active indicator |
| Dot Empty | `○` | `visual.dot_empty` | Step inactive indicator |
| Badge Left | ` ` | `visual.badge_left` | Left wrapper for badges |
| Badge Right | ` ` | `visual.badge_right` | Right wrapper for badges |
| Expand Open | `▼` | `visual.expand_open` | Collapsible section open |
| Expand Closed | `▶` | `visual.expand_closed` | Collapsible section closed |

---

## Pager Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `↑` / `k` | Scroll up |
| `↓` / `j` / `Enter` | Scroll down |
| `Space` / `PageDown` | Page down |
| `b` / `PageUp` | Page up |
| `g` / `Home` | Go to start |
| `G` / `End` | Go to end |
| `s` | Save report |
| `n` | Start new check |
| `q` / `Esc` | Quit |

### Pager Status Bar

The status bar at the bottom of the pager displays:
- Current scroll position
- Available keyboard shortcuts
- Save/quit actions

---

## Unicode Width Handling

### Critical Requirement

All text alignment must account for Unicode character display widths using the `unicode-width` crate.

### Display Width Calculation

```rust
use unicode_width::UnicodeWidthStr;

/// Calculate the display width of a string
fn display_width(s: &str) -> usize {
    UnicodeWidthStr::width(s)
}
```

### Padding to Width

```rust
/// Pad a string to an exact display width
fn pad_to_width(s: &str, width: usize) -> String {
    let current = display_width(s);
    if current >= width {
        s.to_string()
    } else {
        format!("{}{}", s, " ".repeat(width - current))
    }
}
```

### Table Column Alignment

1. Calculate the maximum display width for each column
2. Pad each cell to the column width using `pad_to_width()`
3. Add consistent spacing between columns (2 spaces minimum)

### Common Width Issues

| Character | Appears | Width | Note |
|-----------|---------|-------|------|
| `✓` | 1 cell | 1 | Check mark |
| `✗` | 1 cell | 1 | X mark |
| `!` | 1 cell | 1 | Warning |
| `📄` | 2 cells | 2 | Emoji width |
| `🔒` | 2 cells | 2 | Emoji width |
| `═` | 1 cell | 1 | Box drawing |
| CJK chars | 2 cells | 2 | Full-width characters |

---

## Result Box Structure

Each `TestResult` renders as a structured box with the following sections:

```
╭─ {title} ────────────────────────────────────────────────────────────────╮
│                                                                          │
│  {status_icon} {summary}                                                 │
│                                                                          │
│  ╭─ Additional Details ───────────────────────────────────────────────╮  │
│  │                                                                    │  │
│  │  {DetailSection content - KeyValue, Table, List, or Text}          │  │
│  │                                                                    │  │
│  ╰────────────────────────────────────────────────────────────────────╯  │
│                                                                          │
│  ╭─ Test Steps ───────────────────────────────────────────────────────╮  │
│  │                                                                    │  │
│  │  ✓ Step description                                                │  │
│  │    Result: step details                                            │  │
│  │                                                                    │  │
│  ╰────────────────────────────────────────────────────────────────────╯  │
│                                                                          │
│  ╭─ Recommendations ──────────────────────────────────────────────────╮  │
│  │                                                                    │  │
│  │  i Recommendation text here                                        │  │
│  │  i Another recommendation                                          │  │
│  │                                                                    │  │
│  ╰────────────────────────────────────────────────────────────────────╯  │
│                                                                          │
╰──────────────────────────────────────────────────────────────────────────╯
```

---

## Terminal Compatibility

### Minimum Requirements

- Terminal width: 80 columns (dynamic, prefer full width)
- Unicode support: Required
- 256-color support: Required for best experience
- True color: Optional, falls back to 256-color

### Tested Terminals

- **macOS**: iTerm2, Terminal.app
- **Linux**: GNOME Terminal, Konsole, Alacritty, kitty
- **Windows**: Windows Terminal, ConEmu

### Dynamic Width Calculation

Never assume a fixed terminal width. Always calculate available width:

```rust
let terminal_width = crossterm::terminal::size()?.0;
let content_width = terminal_width.saturating_sub(4); // Account for borders
```

---

## Accessibility Considerations

### Color Independence

Never rely solely on color to convey information. Always pair colors with:
- Status icons (`✓`, `✗`, `!`)
- Text labels ("Pass", "Fail", "Warning")
- Positional context

### High Contrast

All status colors meet WCAG AA contrast requirements against the dark background.
