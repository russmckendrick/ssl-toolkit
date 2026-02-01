//! JSON output formatter

use crate::runner::RunResult;
use serde::Serialize;

/// JSON-serializable output structure
#[derive(Serialize)]
pub struct JsonOutput {
    pub domain: String,
    pub ip: String,
    pub port: u16,
    pub grade: String,
    pub score: u32,
    pub report: crate::models::ReportCard,
    pub cert_comparison: crate::models::CertComparison,
}

/// Print RunResult as JSON to stdout
pub fn print_json(result: &RunResult) -> anyhow::Result<()> {
    let output = JsonOutput {
        domain: result.report.domain.clone(),
        ip: result.report.ip.clone(),
        port: result.report.port,
        grade: result.report.grade.as_str().to_string(),
        score: result.report.score,
        report: result.report.clone(),
        cert_comparison: result.cert_comparison.clone(),
    };

    let json = serde_json::to_string_pretty(&output)?;
    println!("{}", json);
    Ok(())
}
