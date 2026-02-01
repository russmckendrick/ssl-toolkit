//! HTML report generation
//!
//! Generates self-contained HTML reports with embedded styles.

use crate::config::Theme;
use crate::models::{
    CertComparison, CertificateInfo, CertificateType, CheckStatus, DetailSection, DnsResult, Grade,
    SslInfo, TestResult,
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

/// Data for generating certificate file operation reports.
pub struct CertOpsReportData {
    /// Report title (e.g. "Certificate Info: cert.pem")
    pub title: String,
    /// Check results from the cert operation
    pub results: Vec<TestResult>,
    /// Parsed certificate(s) for iCal generation
    pub certificates: Vec<CertificateInfo>,
    /// Source file paths
    pub source_files: Vec<String>,
}

impl HtmlReport {
    /// Generate an HTML report for certificate file operations (info/verify).
    pub fn generate_cert_report(
        &self,
        data: &CertOpsReportData,
        output_path: &Path,
    ) -> Result<(), ReportError> {
        let mut env = Environment::new();
        env.add_template("cert_report", CERT_REPORT_TEMPLATE)
            .map_err(|e| ReportError::TemplateError {
                message: e.to_string(),
            })?;

        let template = env
            .get_template("cert_report")
            .map_err(|e| ReportError::TemplateError {
                message: e.to_string(),
            })?;

        // Build check results for template
        let check_results: Vec<_> = data
            .results
            .iter()
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

                // Build detail sections
                let details: Vec<_> = r
                    .details
                    .iter()
                    .map(|d| match d {
                        DetailSection::KeyValue { title, pairs } => {
                            let items: Vec<_> = pairs
                                .iter()
                                .map(|(k, v)| {
                                    context! { label => k, value => v }
                                })
                                .collect();
                            context! {
                                kind => "key_value",
                                title => title.as_deref().unwrap_or(""),
                                has_title => title.is_some(),
                                items => items,
                            }
                        }
                        DetailSection::List { title, items } => {
                            context! {
                                kind => "list",
                                title => title.as_deref().unwrap_or(""),
                                has_title => title.is_some(),
                                items => items,
                            }
                        }
                        DetailSection::Text { title, content } => {
                            context! {
                                kind => "text",
                                title => title.as_deref().unwrap_or(""),
                                has_title => title.is_some(),
                                content => content,
                            }
                        }
                        _ => {
                            context! {
                                kind => "unknown",
                                title => "",
                                has_title => false,
                            }
                        }
                    })
                    .collect();

                let recommendations = &r.recommendations;

                context! {
                    title => &r.title,
                    status_color => status_color,
                    status_icon => status_icon,
                    summary => &r.summary,
                    steps => steps,
                    has_steps => !r.test_steps.is_empty(),
                    details => details,
                    has_details => !r.details.is_empty(),
                    recommendations => recommendations,
                    has_recommendations => !r.recommendations.is_empty(),
                }
            })
            .collect();

        // Build iCal downloads
        let ical_downloads: Vec<_> = data
            .certificates
            .iter()
            .map(|cert| {
                let label = cert.subject.clone();
                let ical_content = super::ical::IcalGenerator::generate(&cert.subject, cert);
                let ical_base64 = base64::engine::general_purpose::STANDARD.encode(&ical_content);
                // Sanitise the subject for a safe filename
                let safe_name: String = cert
                    .subject
                    .replace("CN=", "")
                    .chars()
                    .map(|c| {
                        if c.is_alphanumeric() || c == '-' || c == '.' {
                            c
                        } else {
                            '_'
                        }
                    })
                    .collect();
                let filename = format!("{}-expiry.ics", safe_name);
                context! {
                    label => label,
                    ical_base64 => ical_base64,
                    filename => filename,
                }
            })
            .collect();

        // Collect all recommendations
        let all_recommendations: Vec<String> = data
            .results
            .iter()
            .flat_map(|r| r.recommendations.clone())
            .collect();

        let html = template
            .render(context! {
                title => &data.title,
                timestamp => chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                source_files => &data.source_files,
                has_source_files => !data.source_files.is_empty(),
                check_results => check_results,
                ical_downloads => ical_downloads,
                has_ical_downloads => !ical_downloads.is_empty(),
                recommendations => all_recommendations,
                has_recommendations => !all_recommendations.is_empty(),
                pass_color => &self.theme.colors.pass,
                fail_color => &self.theme.colors.fail,
                warning_color => &self.theme.colors.warning,
                primary_color => &self.theme.colors.primary,
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

const REPORT_TEMPLATE: &str = include_str!("../../templates/domain_report.html");

const CERT_REPORT_TEMPLATE: &str = include_str!("../../templates/cert_report.html");
