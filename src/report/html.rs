//! HTML report generation
//!
//! Generates self-contained HTML reports with embedded styles.

use crate::config::Theme;
use crate::models::{
    CertComparison, CertificateInfo, CertificateType, CheckStatus, DnsResult, Grade, SslInfo,
};
use crate::report::pem::PemExporter;
use crate::runner::RunResult;
use crate::utils::ReportError;
use base64::Engine;
use minijinja::{context, Environment};
use std::path::Path;

/// HTML report generator
pub struct HtmlReport {
    theme: Theme,
}

impl HtmlReport {
    /// Create a new HTML report generator
    pub fn new(theme: Theme) -> Self {
        Self { theme }
    }

    /// Generate an HTML report from a complete RunResult
    pub fn generate_from_result(
        &self,
        domain: &str,
        run_result: &RunResult,
        output_path: &Path,
    ) -> Result<(), ReportError> {
        let ssl_info = run_result
            .ssl_info
            .as_ref()
            .ok_or(ReportError::TemplateError {
                message: "No SSL info available for report".to_string(),
            })?;
        let cert_info = run_result
            .cert_info
            .as_ref()
            .ok_or(ReportError::TemplateError {
                message: "No certificate info available for report".to_string(),
            })?;

        let mut env = Environment::new();
        env.add_template("report", REPORT_TEMPLATE)
            .map_err(|e| ReportError::TemplateError {
                message: e.to_string(),
            })?;

        let template = env
            .get_template("report")
            .map_err(|e| ReportError::TemplateError {
                message: e.to_string(),
            })?;

        // Generate PEM for download
        let chain_pem = PemExporter::export_chain_without_leaf(&ssl_info.certificate_chain);
        let pem_base64 = base64::engine::general_purpose::STANDARD.encode(&chain_pem);

        // Generate iCal for download
        let ical_content = super::ical::IcalGenerator::generate(domain, cert_info);
        let ical_base64 = base64::engine::general_purpose::STANDARD.encode(&ical_content);

        // Build DNS results for template
        let dns_data: Vec<_> = run_result
            .dns_results
            .iter()
            .map(|r| {
                let addrs: Vec<String> = r.addresses.iter().map(|a| a.to_string()).collect();
                context! {
                    provider => &r.provider,
                    success => r.is_success(),
                    addresses => addrs,
                    query_time_ms => format!("{:.2}", r.query_time.as_secs_f64() * 1000.0),
                    error => &r.error,
                }
            })
            .collect();

        // Build score breakdown
        let report = &run_result.report;
        let score_breakdown = build_score_breakdown(report);

        // Build check results (test steps)
        let check_results = build_check_results(report);

        // Build certificate chain
        let (chain_certificates, has_chain_detail) = build_chain_certificates(report);

        // Build protocol support
        let supported_protocols: Vec<_> = ssl_info
            .supported_protocols
            .iter()
            .map(|p| {
                context! {
                    name => p.protocol.to_string(),
                    supported => p.supported,
                    preferred => p.preferred,
                    is_secure => p.protocol.is_secure(),
                    is_deprecated => p.protocol.is_deprecated(),
                }
            })
            .collect();

        // Build cipher detail
        let cipher_detail = if let Some(cipher) = ssl_info.cipher_suites.first() {
            context! {
                name => &cipher.name,
                key_exchange => &cipher.key_exchange,
                authentication => &cipher.authentication,
                encryption => &cipher.encryption,
                mac => &cipher.mac,
                key_size => cipher.key_size,
                is_secure => cipher.is_secure,
                has_weakness => cipher.has_weakness,
            }
        } else {
            context! {
                name => &ssl_info.cipher_suite,
                key_exchange => "Unknown",
                authentication => "Unknown",
                encryption => "Unknown",
                mac => "Unknown",
                key_size => 0u32,
                is_secure => true,
                has_weakness => false,
            }
        };

        // Recommendations
        let recommendations = report.all_recommendations();
        let has_recommendations = !recommendations.is_empty();

        // Certificate comparison
        let (has_comparison, comparison_has_differences, comparison_summary, comparison_entries) =
            build_comparison_data(&run_result.cert_comparison);

        // WHOIS data
        let whois_data = build_whois_data(report);

        // Render template
        let html = template
            .render(context! {
                domain => domain,
                timestamp => chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                grade => report.grade.as_str(),
                grade_color => report.grade.color(),
                score => report.score,
                ip => ssl_info.ip.to_string(),
                port => ssl_info.port,
                protocol => ssl_info.protocol.to_string(),
                cipher_suite => &ssl_info.cipher_suite,
                subject => &cert_info.subject,
                issuer => &cert_info.issuer,
                serial => &cert_info.serial,
                thumbprint => &cert_info.thumbprint,
                not_before => cert_info.not_before.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                not_after => cert_info.not_after.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                days_until_expiry => cert_info.days_until_expiry(),
                san => &cert_info.san,
                public_key_algorithm => &cert_info.public_key_algorithm,
                public_key_size => cert_info.public_key_size,
                signature_algorithm => &cert_info.signature_algorithm,
                is_expired => cert_info.is_expired(),
                is_self_signed => cert_info.is_self_signed,
                cert_version => format!("v{}", cert_info.version),
                is_ca => cert_info.is_ca,
                key_usage => &cert_info.key_usage,
                has_key_usage => !cert_info.key_usage.is_empty(),
                extended_key_usage => &cert_info.extended_key_usage,
                has_extended_key_usage => !cert_info.extended_key_usage.is_empty(),
                dns_results => dns_data,
                has_dns => !run_result.dns_results.is_empty(),
                has_chain => ssl_info.certificate_chain.len() > 1,
                pem_base64 => pem_base64,
                ical_base64 => ical_base64,
                pass_color => &self.theme.colors.pass,
                fail_color => &self.theme.colors.fail,
                warning_color => &self.theme.colors.warning,
                primary_color => &self.theme.colors.primary,
                score_breakdown => score_breakdown,
                check_results => check_results,
                chain_certificates => chain_certificates,
                has_chain_detail => has_chain_detail,
                supported_protocols => supported_protocols,
                cipher_detail => cipher_detail,
                secure_renegotiation => ssl_info.secure_renegotiation,
                ocsp_stapling => ssl_info.ocsp_stapling,
                trust_verified => ssl_info.trust_verified,
                recommendations => recommendations,
                has_recommendations => has_recommendations,
                has_comparison => has_comparison,
                comparison_has_differences => comparison_has_differences,
                comparison_summary => comparison_summary,
                comparison_entries => comparison_entries,
                has_whois => whois_data.0,
                whois_entries => whois_data.1,
                whois_status_label => whois_data.2,
                whois_status_color => whois_data.3,
            })
            .map_err(|e| ReportError::TemplateError {
                message: e.to_string(),
            })?;

        // Write to file
        std::fs::write(output_path, html).map_err(|e| ReportError::WriteError {
            path: output_path.display().to_string(),
            message: e.to_string(),
        })?;

        Ok(())
    }

    /// Generate an HTML report (legacy method)
    pub fn generate(
        &self,
        domain: &str,
        ssl_info: &SslInfo,
        cert_info: &CertificateInfo,
        output_path: &Path,
    ) -> Result<(), ReportError> {
        self.generate_full_with_comparison(
            domain,
            ssl_info,
            cert_info,
            &[],
            Grade::F,
            None,
            output_path,
        )
    }

    /// Generate an HTML report with all data including DNS and grade (legacy method)
    pub fn generate_full(
        &self,
        domain: &str,
        ssl_info: &SslInfo,
        cert_info: &CertificateInfo,
        dns_results: &[DnsResult],
        grade: Grade,
        output_path: &Path,
    ) -> Result<(), ReportError> {
        self.generate_full_with_comparison(
            domain,
            ssl_info,
            cert_info,
            dns_results,
            grade,
            None,
            output_path,
        )
    }

    /// Generate an HTML report with all data (legacy method)
    #[allow(clippy::too_many_arguments)]
    pub fn generate_full_with_comparison(
        &self,
        domain: &str,
        ssl_info: &SslInfo,
        cert_info: &CertificateInfo,
        dns_results: &[DnsResult],
        grade: Grade,
        cert_comparison: Option<&CertComparison>,
        output_path: &Path,
    ) -> Result<(), ReportError> {
        let mut env = Environment::new();
        env.add_template("report", REPORT_TEMPLATE)
            .map_err(|e| ReportError::TemplateError {
                message: e.to_string(),
            })?;

        let template = env
            .get_template("report")
            .map_err(|e| ReportError::TemplateError {
                message: e.to_string(),
            })?;

        let chain_pem = PemExporter::export_chain_without_leaf(&ssl_info.certificate_chain);
        let pem_base64 = base64::engine::general_purpose::STANDARD.encode(&chain_pem);
        let ical_content = super::ical::IcalGenerator::generate(domain, cert_info);
        let ical_base64 = base64::engine::general_purpose::STANDARD.encode(&ical_content);

        let dns_data: Vec<_> = dns_results
            .iter()
            .map(|r| {
                let addrs: Vec<String> = r.addresses.iter().map(|a| a.to_string()).collect();
                context! {
                    provider => &r.provider,
                    success => r.is_success(),
                    addresses => addrs,
                    query_time_ms => format!("{:.2}", r.query_time.as_secs_f64() * 1000.0),
                    error => &r.error,
                }
            })
            .collect();

        let (has_comparison, comparison_has_differences, comparison_summary, comparison_entries) =
            if let Some(comparison) = cert_comparison {
                build_comparison_data(comparison)
            } else {
                (false, false, String::new(), vec![])
            };

        // Build protocol support from ssl_info
        let supported_protocols: Vec<_> = ssl_info
            .supported_protocols
            .iter()
            .map(|p| {
                context! {
                    name => p.protocol.to_string(),
                    supported => p.supported,
                    preferred => p.preferred,
                    is_secure => p.protocol.is_secure(),
                    is_deprecated => p.protocol.is_deprecated(),
                }
            })
            .collect();

        let cipher_detail = if let Some(cipher) = ssl_info.cipher_suites.first() {
            context! {
                name => &cipher.name,
                key_exchange => &cipher.key_exchange,
                authentication => &cipher.authentication,
                encryption => &cipher.encryption,
                mac => &cipher.mac,
                key_size => cipher.key_size,
                is_secure => cipher.is_secure,
                has_weakness => cipher.has_weakness,
            }
        } else {
            context! {
                name => &ssl_info.cipher_suite,
                key_exchange => "Unknown",
                authentication => "Unknown",
                encryption => "Unknown",
                mac => "Unknown",
                key_size => 0u32,
                is_secure => true,
                has_weakness => false,
            }
        };

        let html = template
            .render(context! {
                domain => domain,
                timestamp => chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                grade => grade.as_str(),
                grade_color => grade.color(),
                score => 0u32,
                ip => ssl_info.ip.to_string(),
                port => ssl_info.port,
                protocol => ssl_info.protocol.to_string(),
                cipher_suite => &ssl_info.cipher_suite,
                subject => &cert_info.subject,
                issuer => &cert_info.issuer,
                serial => &cert_info.serial,
                thumbprint => &cert_info.thumbprint,
                not_before => cert_info.not_before.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                not_after => cert_info.not_after.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                days_until_expiry => cert_info.days_until_expiry(),
                san => &cert_info.san,
                public_key_algorithm => &cert_info.public_key_algorithm,
                public_key_size => cert_info.public_key_size,
                signature_algorithm => &cert_info.signature_algorithm,
                is_expired => cert_info.is_expired(),
                is_self_signed => cert_info.is_self_signed,
                cert_version => format!("v{}", cert_info.version),
                is_ca => cert_info.is_ca,
                key_usage => &cert_info.key_usage,
                has_key_usage => !cert_info.key_usage.is_empty(),
                extended_key_usage => &cert_info.extended_key_usage,
                has_extended_key_usage => !cert_info.extended_key_usage.is_empty(),
                dns_results => dns_data,
                has_dns => !dns_results.is_empty(),
                has_chain => ssl_info.certificate_chain.len() > 1,
                pem_base64 => pem_base64,
                ical_base64 => ical_base64,
                pass_color => &self.theme.colors.pass,
                fail_color => &self.theme.colors.fail,
                warning_color => &self.theme.colors.warning,
                primary_color => &self.theme.colors.primary,
                score_breakdown => Vec::<minijinja::Value>::new(),
                check_results => Vec::<minijinja::Value>::new(),
                chain_certificates => Vec::<minijinja::Value>::new(),
                has_chain_detail => false,
                supported_protocols => supported_protocols,
                cipher_detail => cipher_detail,
                secure_renegotiation => ssl_info.secure_renegotiation,
                ocsp_stapling => ssl_info.ocsp_stapling,
                trust_verified => ssl_info.trust_verified,
                recommendations => Vec::<String>::new(),
                has_recommendations => false,
                has_comparison => has_comparison,
                comparison_has_differences => comparison_has_differences,
                comparison_summary => comparison_summary,
                comparison_entries => comparison_entries,
                has_whois => false,
                whois_entries => Vec::<minijinja::Value>::new(),
                whois_status_label => "",
                whois_status_color => "",
            })
            .map_err(|e| ReportError::TemplateError {
                message: e.to_string(),
            })?;

        std::fs::write(output_path, html).map_err(|e| ReportError::WriteError {
            path: output_path.display().to_string(),
            message: e.to_string(),
        })?;

        Ok(())
    }
}

/// Build score breakdown data for the template
fn build_score_breakdown(report: &crate::models::ReportCard) -> Vec<minijinja::Value> {
    let checks: Vec<(&str, &Option<crate::models::TestResult>, u32)> = vec![
        ("DNS", &report.dns_result, 10),
        ("TCP", &report.tcp_result, 10),
        ("SSL/TLS", &report.ssl_result, 40),
        ("Certificate", &report.certificate_result, 40),
    ];

    checks
        .into_iter()
        .filter_map(|(name, result, weight)| {
            let result = result.as_ref()?;
            let points = match result.status {
                CheckStatus::Pass => 100u32,
                CheckStatus::Warning => 70,
                CheckStatus::Fail => 0,
            };
            let weighted_score = (points * weight) as f64 / 100.0;
            let (status_label, status_color) = match result.status {
                CheckStatus::Pass => ("Pass", "#10B981"),
                CheckStatus::Warning => ("Warning", "#F59E0B"),
                CheckStatus::Fail => ("Fail", "#EF4444"),
            };
            Some(context! {
                name => name,
                status_label => status_label,
                status_color => status_color,
                points => points,
                weight_pct => weight,
                weighted_score => format!("{:.1}", weighted_score),
            })
        })
        .collect()
}

/// Build check results (diagnostic summary) for the template
fn build_check_results(report: &crate::models::ReportCard) -> Vec<minijinja::Value> {
    let results: Vec<&Option<crate::models::TestResult>> = vec![
        &report.dns_result,
        &report.tcp_result,
        &report.ssl_result,
        &report.certificate_result,
    ];

    results
        .into_iter()
        .filter_map(|r| r.as_ref())
        .map(|r| {
            let (status_color, status_icon) = match r.status {
                CheckStatus::Pass => ("#10B981", "&#10003;"),
                CheckStatus::Warning => ("#F59E0B", "&#9888;"),
                CheckStatus::Fail => ("#EF4444", "&#10007;"),
            };

            let steps: Vec<_> = r
                .test_steps
                .iter()
                .map(|step| {
                    let (step_color, step_icon) = match step.status {
                        CheckStatus::Pass => ("#10B981", "&#10003;"),
                        CheckStatus::Warning => ("#F59E0B", "&#9888;"),
                        CheckStatus::Fail => ("#EF4444", "&#10007;"),
                    };
                    context! {
                        description => &step.description,
                        status_color => step_color,
                        status_icon => step_icon,
                        has_details => step.details.is_some(),
                        details => step.details.as_deref().unwrap_or(""),
                    }
                })
                .collect();

            context! {
                title => &r.title,
                status_color => status_color,
                status_icon => status_icon,
                summary => &r.summary,
                steps => steps,
                has_steps => !r.test_steps.is_empty(),
            }
        })
        .collect()
}

/// Build certificate chain data for the template
fn build_chain_certificates(report: &crate::models::ReportCard) -> (Vec<minijinja::Value>, bool) {
    if let Some(ref cert_result) = report.certificate_result {
        for detail in &cert_result.details {
            if let crate::models::DetailSection::CertificateChain { certificates } = detail {
                let chain: Vec<_> = certificates
                    .iter()
                    .enumerate()
                    .map(|(idx, cert)| {
                        let (icon, type_label) = match cert.cert_type {
                            CertificateType::Leaf => ("&#128196;", "Server Certificate"),
                            CertificateType::Intermediate => ("&#128203;", "Intermediate CA"),
                            CertificateType::Root => ("&#128272;", "Root CA"),
                        };
                        context! {
                            cert_type => type_label,
                            icon => icon,
                            subject_cn => &cert.subject_cn,
                            issuer_cn => &cert.issuer_cn,
                            valid_until => &cert.valid_until,
                            days_until_expiry => cert.days_until_expiry,
                            is_valid => cert.is_valid,
                            is_leaf => cert.cert_type == CertificateType::Leaf,
                            is_root => cert.cert_type == CertificateType::Root,
                            indent => idx * 24,
                        }
                    })
                    .collect();
                return (chain, true);
            }
        }
    }
    (vec![], false)
}

/// Build certificate comparison data for the template
fn build_comparison_data(
    comparison: &CertComparison,
) -> (bool, bool, String, Vec<minijinja::Value>) {
    if comparison.entries.len() > 1 {
        let entries: Vec<_> = comparison
            .entries
            .iter()
            .map(|e| {
                let differences: Vec<String> =
                    e.differences.iter().map(|d| d.description()).collect();
                context! {
                    ip => e.ip.to_string(),
                    thumbprint => &e.thumbprint,
                    subject => &e.subject,
                    issuer => &e.issuer,
                    days_until_expiry => e.days_until_expiry,
                    serial => &e.serial,
                    is_different => e.is_different,
                    has_error => e.error.is_some(),
                    error => &e.error,
                    differences => differences,
                }
            })
            .collect();
        (
            true,
            comparison.has_differences,
            comparison.summary.clone(),
            entries,
        )
    } else {
        (false, false, String::new(), vec![])
    }
}

/// Build WHOIS data for the template
/// Returns (has_whois, entries, status_label, status_color)
fn build_whois_data(
    report: &crate::models::ReportCard,
) -> (bool, Vec<minijinja::Value>, String, String) {
    if let Some(ref whois_result) = report.whois_result {
        let mut entries = Vec::new();

        // Extract key-value pairs from detail sections
        for detail in &whois_result.details {
            if let crate::models::DetailSection::KeyValue { pairs, .. } = detail {
                for (key, value) in pairs {
                    entries.push(context! {
                        label => key,
                        value => value,
                    });
                }
            }
        }

        let (status_label, status_color) = match whois_result.status {
            CheckStatus::Pass => ("Retrieved".to_string(), "#10B981".to_string()),
            CheckStatus::Warning => ("Partial".to_string(), "#F59E0B".to_string()),
            CheckStatus::Fail => ("Failed".to_string(), "#EF4444".to_string()),
        };

        (true, entries, status_label, status_color)
    } else {
        (false, vec![], String::new(), String::new())
    }
}

const REPORT_TEMPLATE: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSL Report - {{ domain }}</title>
    <style>
        :root {
            --pass: {{ pass_color }};
            --fail: {{ fail_color }};
            --warning: {{ warning_color }};
            --primary: {{ primary_color }};
            --bg: #1a1a2e;
            --card-bg: #16213e;
            --text: #eaeaea;
            --text-muted: #8892a0;
            --border: #0f3460;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 2rem;
        }

        .container {
            max-width: 900px;
            margin: 0 auto;
        }

        header {
            text-align: center;
            margin-bottom: 2rem;
            padding-bottom: 1rem;
            border-bottom: 2px solid var(--border);
        }

        h1 {
            color: var(--primary);
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }

        .domain {
            font-size: 1.5rem;
            color: var(--text);
        }

        .timestamp {
            color: var(--text-muted);
            font-size: 0.9rem;
        }

        .grade-box {
            display: inline-block;
            margin-top: 1rem;
            padding: 0.5rem 2rem;
            border: 3px solid;
            border-radius: 8px;
            font-size: 2rem;
            font-weight: bold;
        }

        .score {
            display: block;
            font-size: 0.9rem;
            font-weight: normal;
            margin-top: 0.25rem;
            opacity: 0.85;
        }

        .card {
            background: var(--card-bg);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            border: 1px solid var(--border);
        }

        .card h2 {
            color: var(--primary);
            margin-bottom: 1rem;
            font-size: 1.25rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .status-badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            font-size: 0.875rem;
            font-weight: 600;
        }

        .status-pass {
            background: var(--pass);
            color: white;
        }

        .status-fail {
            background: var(--fail);
            color: white;
        }

        .status-warning {
            background: var(--warning);
            color: black;
        }

        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }

        .info-item {
            padding: 0.75rem;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 4px;
        }

        .info-item.full-width {
            grid-column: 1 / -1;
        }

        .info-label {
            color: var(--text-muted);
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .info-value {
            font-size: 1rem;
            word-break: break-all;
        }

        .san-list {
            list-style: none;
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
        }

        .san-item {
            background: rgba(255, 255, 255, 0.1);
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.9rem;
        }

        /* Score breakdown table */
        .score-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 0.5rem;
        }

        .score-table th, .score-table td {
            padding: 0.6rem 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }

        .score-table th {
            color: var(--text-muted);
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .score-table .total-row td {
            border-top: 2px solid var(--border);
            font-weight: 600;
            padding-top: 0.75rem;
        }

        /* Diagnostic test steps */
        .check-card {
            margin-bottom: 1rem;
        }

        .check-card:last-child {
            margin-bottom: 0;
        }

        .check-header {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin-bottom: 0.5rem;
        }

        .check-icon {
            font-size: 1.1rem;
            width: 1.5rem;
            text-align: center;
        }

        .check-title {
            font-weight: 600;
            font-size: 1rem;
        }

        .check-summary {
            font-size: 0.85rem;
            margin-left: auto;
        }

        .test-steps {
            margin-left: 1.75rem;
            border-left: 2px solid var(--border);
            padding-left: 1rem;
        }

        .test-step {
            display: flex;
            align-items: flex-start;
            gap: 0.5rem;
            padding: 0.35rem 0;
            border-bottom: 1px solid rgba(255, 255, 255, 0.03);
        }

        .test-step:last-child {
            border-bottom: none;
        }

        .step-icon {
            width: 1rem;
            text-align: center;
            flex-shrink: 0;
            font-size: 0.85rem;
            margin-top: 0.1rem;
        }

        .step-desc {
            font-size: 0.9rem;
        }

        .step-details {
            color: var(--text-muted);
            font-size: 0.8rem;
            margin-left: 1.5rem;
            margin-top: 0.15rem;
        }

        /* Certificate chain tree */
        .chain-tree {
            margin-top: 0.5rem;
        }

        .chain-node {
            padding: 0.6rem 0.75rem;
            background: rgba(255, 255, 255, 0.03);
            border-radius: 4px;
            margin-bottom: 0.5rem;
            border-left: 3px solid var(--border);
        }

        .chain-node.valid {
            border-left-color: var(--pass);
        }

        .chain-node.expired {
            border-left-color: var(--fail);
        }

        .chain-node.expiring {
            border-left-color: var(--warning);
        }

        .chain-header {
            display: flex;
            align-items: center;
            gap: 0.4rem;
            margin-bottom: 0.25rem;
        }

        .chain-icon {
            font-size: 1rem;
        }

        .chain-type {
            font-weight: 600;
            font-size: 0.85rem;
        }

        .chain-cn {
            font-family: monospace;
            font-size: 0.9rem;
            color: var(--text);
        }

        .chain-meta {
            font-size: 0.8rem;
            color: var(--text-muted);
            margin-top: 0.15rem;
        }

        /* Protocol table */
        .protocol-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 0.5rem;
        }

        .protocol-table th, .protocol-table td {
            padding: 0.5rem 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }

        .protocol-table th {
            color: var(--text-muted);
            font-size: 0.8rem;
            text-transform: uppercase;
        }

        .status-green { color: var(--pass); }
        .status-yellow { color: var(--warning); }
        .status-red { color: var(--fail); }

        /* Recommendations */
        .recommendations-list {
            list-style: none;
        }

        .recommendation-item {
            padding: 0.6rem 0.75rem;
            margin-bottom: 0.5rem;
            border-left: 3px solid var(--warning);
            background: rgba(245, 158, 11, 0.08);
            border-radius: 0 4px 4px 0;
            font-size: 0.9rem;
        }

        .recommendation-item:last-child {
            margin-bottom: 0;
        }

        /* DNS table */
        .dns-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 0.5rem;
        }

        .dns-table th, .dns-table td {
            padding: 0.5rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }

        .dns-table th {
            color: var(--text-muted);
            font-size: 0.8rem;
            text-transform: uppercase;
        }

        .dns-status {
            display: inline-block;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            margin-right: 0.5rem;
        }

        .dns-status.success {
            background: var(--pass);
        }

        .dns-status.fail {
            background: var(--fail);
        }

        /* Comparison table */
        .comparison-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 0.5rem;
        }

        .comparison-table th, .comparison-table td {
            padding: 0.5rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }

        .comparison-table th {
            color: var(--text-muted);
            font-size: 0.8rem;
            text-transform: uppercase;
        }

        .comparison-status {
            display: inline-flex;
            align-items: center;
            gap: 0.25rem;
        }

        .comparison-status.match {
            color: var(--pass);
        }

        .comparison-status.different {
            color: var(--warning);
        }

        .comparison-status.error {
            color: var(--fail);
        }

        .diff-list {
            list-style: none;
            margin-top: 0.25rem;
            font-size: 0.85rem;
        }

        .diff-list li {
            color: var(--warning);
            padding: 0.1rem 0;
        }

        .comparison-summary {
            padding: 0.75rem;
            border-radius: 4px;
            margin-bottom: 1rem;
        }

        .comparison-summary.has-differences {
            background: rgba(245, 158, 11, 0.1);
            border-left: 3px solid var(--warning);
        }

        .comparison-summary.all-match {
            background: rgba(16, 185, 129, 0.1);
            border-left: 3px solid var(--pass);
        }

        .downloads {
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
        }

        .download-btn {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.75rem 1.5rem;
            background: var(--primary);
            color: white;
            text-decoration: none;
            border-radius: 6px;
            font-weight: 500;
            transition: opacity 0.2s;
        }

        .download-btn:hover {
            opacity: 0.9;
        }

        .download-btn.disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }

        footer {
            text-align: center;
            margin-top: 2rem;
            padding-top: 1rem;
            border-top: 1px solid var(--border);
            color: var(--text-muted);
            font-size: 0.875rem;
        }

        @media (max-width: 600px) {
            body {
                padding: 1rem;
            }

            .info-grid {
                grid-template-columns: 1fr;
            }

            .check-header {
                flex-wrap: wrap;
            }

            .check-summary {
                margin-left: 1.75rem;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>SSL/TLS Diagnostic Report</h1>
            <p class="domain">{{ domain }}</p>
            <p class="timestamp">Generated: {{ timestamp }}</p>
            <div class="grade-box" style="border-color: {{ grade_color }}; color: {{ grade_color }};">
                Grade: {{ grade }}
                {% if score > 0 %}
                <span class="score">Score: {{ score }}/100</span>
                {% endif %}
            </div>
        </header>

        {# ── Score Breakdown ── #}
        {% if score_breakdown %}
        <div class="card">
            <h2>Score Breakdown</h2>
            <table class="score-table">
                <thead>
                    <tr>
                        <th>Check</th>
                        <th>Status</th>
                        <th>Points</th>
                        <th>Weight</th>
                        <th>Weighted</th>
                    </tr>
                </thead>
                <tbody>
                    {% for item in score_breakdown %}
                    <tr>
                        <td>{{ item.name }}</td>
                        <td><span class="status-badge" style="background: {{ item.status_color }}; color: {% if item.status_label == 'Warning' %}black{% else %}white{% endif %};">{{ item.status_label }}</span></td>
                        <td>{{ item.points }}</td>
                        <td>{{ item.weight_pct }}%</td>
                        <td>{{ item.weighted_score }}</td>
                    </tr>
                    {% endfor %}
                    <tr class="total-row">
                        <td colspan="4" style="text-align: right;">Total Score</td>
                        <td style="color: {{ grade_color }};">{{ score }}/100 &mdash; {{ grade }}</td>
                    </tr>
                </tbody>
            </table>
        </div>
        {% endif %}

        {# ── Diagnostic Summary ── #}
        {% if check_results %}
        <div class="card">
            <h2>Diagnostic Summary</h2>
            {% for check in check_results %}
            <div class="check-card">
                <div class="check-header">
                    <span class="check-icon" style="color: {{ check.status_color }};">{{ check.status_icon }}</span>
                    <span class="check-title">{{ check.title }}</span>
                    <span class="check-summary" style="color: {{ check.status_color }};">{{ check.summary }}</span>
                </div>
                {% if check.has_steps %}
                <div class="test-steps">
                    {% for step in check.steps %}
                    <div class="test-step">
                        <span class="step-icon" style="color: {{ step.status_color }};">{{ step.status_icon }}</span>
                        <span class="step-desc">{{ step.description }}</span>
                    </div>
                    {% if step.has_details %}
                    <div class="step-details">{{ step.details }}</div>
                    {% endif %}
                    {% endfor %}
                </div>
                {% endif %}
            </div>
            {% endfor %}
        </div>
        {% endif %}

        {# ── Certificate Status ── #}
        <div class="card">
            <h2>
                Certificate Status
                {% if is_expired %}
                <span class="status-badge status-fail">Expired</span>
                {% elif days_until_expiry < 30 %}
                <span class="status-badge status-warning">Expiring Soon</span>
                {% else %}
                <span class="status-badge status-pass">Valid</span>
                {% endif %}
                {% if is_self_signed %}
                <span class="status-badge status-warning">Self-Signed</span>
                {% endif %}
                {% if not trust_verified %}
                <span class="status-badge status-fail">Untrusted Chain</span>
                {% endif %}
            </h2>
            <div class="info-grid">
                <div class="info-item">
                    <div class="info-label">Days Until Expiry</div>
                    <div class="info-value">{{ days_until_expiry }}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Valid From</div>
                    <div class="info-value">{{ not_before }}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Valid Until</div>
                    <div class="info-value">{{ not_after }}</div>
                </div>
            </div>
        </div>

        {# ── Certificate Chain ── #}
        {% if has_chain_detail %}
        <div class="card">
            <h2>Certificate Chain</h2>
            <div class="chain-tree">
                {% for cert in chain_certificates %}
                <div class="chain-node {% if not cert.is_valid %}expired{% elif cert.days_until_expiry < 30 %}expiring{% else %}valid{% endif %}" style="margin-left: {{ cert.indent }}px;">
                    <div class="chain-header">
                        <span class="chain-icon">{{ cert.icon }}</span>
                        <span class="chain-type">{{ cert.cert_type }}</span>
                        <span class="chain-cn">{{ cert.subject_cn }}</span>
                    </div>
                    <div class="chain-meta">
                        Issuer: {{ cert.issuer_cn }} &middot; Expires: {{ cert.valid_until }} ({{ cert.days_until_expiry }}d)
                    </div>
                </div>
                {% endfor %}
            </div>
        </div>
        {% endif %}

        {# ── Certificate Details ── #}
        <div class="card">
            <h2>Certificate Details</h2>
            <div class="info-grid">
                <div class="info-item">
                    <div class="info-label">Subject</div>
                    <div class="info-value">{{ subject }}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Issuer</div>
                    <div class="info-value">{{ issuer }}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Version</div>
                    <div class="info-value">{{ cert_version }}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">CA Certificate</div>
                    <div class="info-value">{% if is_ca %}Yes{% else %}No{% endif %}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Serial Number</div>
                    <div class="info-value">{{ serial }}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Thumbprint (SHA-256)</div>
                    <div class="info-value">{{ thumbprint }}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Public Key</div>
                    <div class="info-value">{{ public_key_algorithm }} ({{ public_key_size }} bits)</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Signature Algorithm</div>
                    <div class="info-value">{{ signature_algorithm }}</div>
                </div>
                {% if has_key_usage %}
                <div class="info-item full-width">
                    <div class="info-label">Key Usage</div>
                    <div class="info-value">{{ key_usage | join(", ") }}</div>
                </div>
                {% endif %}
                {% if has_extended_key_usage %}
                <div class="info-item full-width">
                    <div class="info-label">Extended Key Usage</div>
                    <div class="info-value">{{ extended_key_usage | join(", ") }}</div>
                </div>
                {% endif %}
            </div>
        </div>

        {# ── Protocol Support ── #}
        {% if supported_protocols %}
        <div class="card">
            <h2>Protocol Support</h2>
            <div class="info-grid" style="margin-bottom: 1rem;">
                <div class="info-item">
                    <div class="info-label">Secure Renegotiation</div>
                    <div class="info-value {% if secure_renegotiation %}status-green{% else %}status-red{% endif %}">
                        {% if secure_renegotiation %}Supported{% else %}Not Supported{% endif %}
                    </div>
                </div>
                <div class="info-item">
                    <div class="info-label">OCSP Stapling</div>
                    <div class="info-value {% if ocsp_stapling %}status-green{% else %}status-yellow{% endif %}">
                        {% if ocsp_stapling %}Enabled{% else %}Disabled{% endif %}
                    </div>
                </div>
            </div>
            <table class="protocol-table">
                <thead>
                    <tr>
                        <th>Protocol</th>
                        <th>Supported</th>
                        <th>Preferred</th>
                        <th>Security</th>
                    </tr>
                </thead>
                <tbody>
                    {% for proto in supported_protocols %}
                    <tr>
                        <td>{{ proto.name }}</td>
                        <td>
                            {% if proto.supported %}
                            <span class="{% if proto.is_secure %}status-green{% else %}status-red{% endif %}">Yes</span>
                            {% else %}
                            <span class="status-green">No</span>
                            {% endif %}
                        </td>
                        <td>{% if proto.preferred %}<span class="status-green">Yes</span>{% else %}-{% endif %}</td>
                        <td>
                            {% if proto.is_deprecated %}
                            <span class="status-red">Deprecated</span>
                            {% else %}
                            <span class="status-green">Secure</span>
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

        {# ── Cipher Suite Details ── #}
        <div class="card">
            <h2>
                Cipher Suite Details
                {% if cipher_detail.is_secure and not cipher_detail.has_weakness %}
                <span class="status-badge status-pass">Secure</span>
                {% elif cipher_detail.has_weakness %}
                <span class="status-badge status-warning">Weak</span>
                {% elif not cipher_detail.is_secure %}
                <span class="status-badge status-fail">Insecure</span>
                {% endif %}
            </h2>
            <div class="info-grid">
                <div class="info-item full-width">
                    <div class="info-label">Cipher Suite</div>
                    <div class="info-value" style="font-family: monospace;">{{ cipher_detail.name }}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Key Exchange</div>
                    <div class="info-value">{{ cipher_detail.key_exchange }}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Authentication</div>
                    <div class="info-value">{{ cipher_detail.authentication }}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Encryption</div>
                    <div class="info-value">{{ cipher_detail.encryption }}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">MAC</div>
                    <div class="info-value">{{ cipher_detail.mac }}</div>
                </div>
                {% if cipher_detail.key_size > 0 %}
                <div class="info-item">
                    <div class="info-label">Key Size</div>
                    <div class="info-value">{{ cipher_detail.key_size }} bits</div>
                </div>
                {% endif %}
            </div>
        </div>

        {# ── DNS Resolution ── #}
        {% if has_dns %}
        <div class="card">
            <h2>DNS Resolution</h2>
            <table class="dns-table">
                <thead>
                    <tr>
                        <th>Provider</th>
                        <th>Status</th>
                        <th>IP Addresses</th>
                        <th>Time</th>
                    </tr>
                </thead>
                <tbody>
                    {% for dns in dns_results %}
                    <tr>
                        <td>{{ dns.provider }}</td>
                        <td>
                            <span class="dns-status {% if dns.success %}success{% else %}fail{% endif %}"></span>
                            {% if dns.success %}OK{% else %}Failed{% endif %}
                        </td>
                        <td>{% if dns.success %}{{ dns.addresses | join(", ") }}{% else %}{{ dns.error }}{% endif %}</td>
                        <td>{{ dns.query_time_ms }}ms</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

        {# ── WHOIS Domain Registration ── #}
        {% if has_whois %}
        <div class="card">
            <h2>
                WHOIS Domain Registration
                <span class="status-badge" style="background: {{ whois_status_color }}; color: white;">{{ whois_status_label }}</span>
            </h2>
            {% if whois_entries %}
            <div class="info-grid">
                {% for entry in whois_entries %}
                <div class="info-item{% if entry.label == 'Nameservers' or entry.label == 'Status' %} full-width{% endif %}">
                    <div class="info-label">{{ entry.label }}</div>
                    <div class="info-value">{{ entry.value }}</div>
                </div>
                {% endfor %}
            </div>
            {% endif %}
        </div>
        {% endif %}

        {# ── Subject Alternative Names ── #}
        {% if san %}
        <div class="card">
            <h2>Subject Alternative Names</h2>
            <ul class="san-list">
                {% for name in san %}
                <li class="san-item">{{ name }}</li>
                {% endfor %}
            </ul>
        </div>
        {% endif %}

        {# ── Certificate Comparison ── #}
        {% if has_comparison %}
        <div class="card">
            <h2>
                Certificate Comparison Across IPs
                {% if comparison_has_differences %}
                <span class="status-badge status-warning">Differences Found</span>
                {% else %}
                <span class="status-badge status-pass">All Match</span>
                {% endif %}
            </h2>
            <div class="comparison-summary {% if comparison_has_differences %}has-differences{% else %}all-match{% endif %}">
                {{ comparison_summary }}
            </div>
            <table class="comparison-table">
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Status</th>
                        <th>Subject</th>
                        <th>Expiry (Days)</th>
                    </tr>
                </thead>
                <tbody>
                    {% for entry in comparison_entries %}
                    <tr>
                        <td><code>{{ entry.ip }}</code></td>
                        <td>
                            {% if entry.has_error %}
                            <span class="comparison-status error">&#10007; Error</span>
                            {% elif entry.is_different %}
                            <span class="comparison-status different">&#9888; Different</span>
                            {% else %}
                            <span class="comparison-status match">&#10003; Match</span>
                            {% endif %}
                        </td>
                        <td>
                            {% if entry.has_error %}
                            <span style="color: var(--fail);">{{ entry.error }}</span>
                            {% else %}
                            {{ entry.subject }}
                            {% endif %}
                        </td>
                        <td>
                            {% if entry.has_error %}
                            -
                            {% else %}
                            {{ entry.days_until_expiry }}
                            {% endif %}
                        </td>
                    </tr>
                    {% if entry.is_different and entry.differences %}
                    <tr>
                        <td colspan="4">
                            <ul class="diff-list">
                                {% for diff in entry.differences %}
                                <li>&bull; {{ diff }}</li>
                                {% endfor %}
                            </ul>
                        </td>
                    </tr>
                    {% endif %}
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

        {# ── Recommendations ── #}
        {% if has_recommendations %}
        <div class="card">
            <h2>Recommendations</h2>
            <ul class="recommendations-list">
                {% for rec in recommendations %}
                <li class="recommendation-item">{{ rec }}</li>
                {% endfor %}
            </ul>
        </div>
        {% endif %}

        {# ── Downloads ── #}
        <div class="card">
            <h2>Downloads</h2>
            <div class="downloads">
                {% if has_chain %}
                <a href="data:application/x-pem-file;base64,{{ pem_base64 }}"
                   download="{{ domain }}-chain.pem"
                   class="download-btn">
                    Download Certificate Chain (PEM)
                </a>
                {% else %}
                <span class="download-btn disabled">
                    No Chain Available
                </span>
                {% endif %}
                <a href="data:text/calendar;base64,{{ ical_base64 }}"
                   download="{{ domain }}-expiry.ics"
                   class="download-btn">
                    Download Expiry Reminder (iCal)
                </a>
            </div>
        </div>

        <footer>
            <p>Generated by SSL-Toolkit</p>
        </footer>
    </div>
</body>
</html>"#;
