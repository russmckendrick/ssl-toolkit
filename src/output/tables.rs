//! Table rendering using comfy-table

use comfy_table::{presets::UTF8_FULL_CONDENSED, Attribute, Cell, Color, ContentArrangement, Table};

/// Print a formatted table with headers and rows
pub fn print_table(headers: &[String], rows: &[Vec<String>]) {
    let mut table = Table::new();
    table.load_preset(UTF8_FULL_CONDENSED);

    // Constrain table width to terminal width minus indent
    if let Ok((cols, _)) = crossterm::terminal::size() {
        table.set_width(cols.saturating_sub(4));
    }
    table.set_content_arrangement(ContentArrangement::Dynamic);

    // Add header row with styling
    let header_cells: Vec<Cell> = headers
        .iter()
        .map(|h| Cell::new(h).add_attribute(Attribute::Bold).fg(Color::Cyan))
        .collect();
    table.set_header(header_cells);

    // Add data rows
    for row in rows {
        let cells: Vec<Cell> = row
            .iter()
            .map(|cell_text| {
                let mut cell = Cell::new(cell_text);
                // Color status cells
                if cell_text.contains("✓") {
                    cell = cell.fg(Color::Green);
                } else if cell_text.contains("✗") {
                    cell = cell.fg(Color::Red);
                }
                cell
            })
            .collect();
        table.add_row(cells);
    }

    // Indent the table
    for line in table.to_string().lines() {
        println!("    {}", line);
    }
}

/// Format a table to a string (for paged output)
pub fn format_table(headers: &[String], rows: &[Vec<String>]) -> String {
    let mut table = Table::new();
    table.load_preset(UTF8_FULL_CONDENSED);

    // Constrain table width to terminal width minus indent, default to 120 if detection fails
    let width = crossterm::terminal::size()
        .map(|(cols, _)| cols)
        .unwrap_or(120)
        .saturating_sub(4);
    table.set_width(width);
    table.set_content_arrangement(ContentArrangement::Dynamic);

    let header_cells: Vec<Cell> = headers
        .iter()
        .map(|h| Cell::new(h).add_attribute(Attribute::Bold).fg(Color::Cyan))
        .collect();
    table.set_header(header_cells);

    for row in rows {
        let cells: Vec<Cell> = row
            .iter()
            .map(|cell_text| {
                let mut cell = Cell::new(cell_text);
                if cell_text.contains("✓") {
                    cell = cell.fg(Color::Green);
                } else if cell_text.contains("✗") {
                    cell = cell.fg(Color::Red);
                }
                cell
            })
            .collect();
        table.add_row(cells);
    }

    let mut out = String::new();
    for line in table.to_string().lines() {
        out.push_str(&format!("    {}\n", line));
    }
    out
}

/// Print a DNS results table
pub fn print_dns_table(
    results: &[(String, bool, String, String)], // (provider, success, ips, time)
) {
    let headers = vec![
        "Provider".to_string(),
        "Status".to_string(),
        "IP Addresses".to_string(),
        "Time".to_string(),
    ];

    let rows: Vec<Vec<String>> = results
        .iter()
        .map(|(provider, success, ips, time)| {
            vec![
                provider.clone(),
                if *success {
                    "✓ OK".to_string()
                } else {
                    "✗ Failed".to_string()
                },
                ips.clone(),
                time.clone(),
            ]
        })
        .collect();

    print_table(&headers, &rows);
}
