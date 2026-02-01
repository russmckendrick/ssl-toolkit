//! Runner for cert subcommand operations
//!
//! Orchestrates cert info, verify, and convert operations, producing
//! TestResult objects compatible with existing output formatters.

use crate::cert_ops::{chain_verify, convert, key_match, reader};
use crate::checks::CertificateChecker;
use crate::cli::{CertConvertArgs, CertFormat, CertInfoArgs, CertVerifyArgs};
use crate::config;
use crate::models::{CertificateInfo, CheckStatus, DetailSection, TestResult, TestStep};
use crate::output::interactive::{self, CertVerifyMode};
use crate::output::{pager, results};
use crate::report::{html::CertOpsReportData, HtmlReport};
use crate::utils::CertFileError;
use chrono::Local;
use console::style;
use std::path::{Path, PathBuf};

/// Resolve the password for a PKCS#12 file.
///
/// If a password was given explicitly, return it. Otherwise try empty password,
/// and if that fails, prompt interactively.
fn resolve_pkcs12_password(path: &Path, password: Option<&str>) -> Result<String, anyhow::Error> {
    if let Some(pwd) = password {
        return Ok(pwd.to_string());
    }

    // Try empty password
    if reader::read_certificates(path, Some("")).is_ok() {
        return Ok(String::new());
    }

    // Prompt if interactive
    if console::Term::stderr().is_term() {
        let pwd = dialoguer::Password::new()
            .with_prompt(format!(
                "Password for {}",
                path.file_name().unwrap_or_default().to_string_lossy()
            ))
            .allow_empty_password(true)
            .interact()?;
        Ok(pwd)
    } else {
        anyhow::bail!(
            "PKCS#12 file {} requires a password (use --password)",
            path.display()
        );
    }
}

/// Read certificates from a file, prompting for a PKCS#12 password if needed.
///
/// If the file is PKCS#12, no password was supplied, and the initial attempt
/// fails (e.g. MAC mismatch), the user is prompted interactively.
fn read_certs_with_password_prompt(
    path: &Path,
    password: Option<&str>,
) -> Result<(Vec<Vec<u8>>, reader::DetectedFormat), anyhow::Error> {
    let format = reader::detect_format(path)?;

    // For non-PKCS#12, or when a password was explicitly provided, just try once.
    if format != reader::DetectedFormat::Pkcs12 || password.is_some() {
        let certs = reader::read_certificates(path, password)?;
        return Ok((certs, format));
    }

    // PKCS#12 with no password supplied — try empty password first.
    match reader::read_certificates(path, Some("")) {
        Ok(certs) => Ok((certs, format)),
        Err(_) => {
            // Empty password failed — prompt if we have a terminal.
            if console::Term::stderr().is_term() {
                let pwd = dialoguer::Password::new()
                    .with_prompt(format!(
                        "Password for {}",
                        path.file_name().unwrap_or_default().to_string_lossy()
                    ))
                    .allow_empty_password(true)
                    .interact()?;

                let certs = reader::read_certificates(path, Some(&pwd))?;
                Ok((certs, format))
            } else {
                anyhow::bail!(
                    "PKCS#12 file {} requires a password (use --password)",
                    path.display()
                );
            }
        }
    }
}

/// Collect cert info results without printing.
fn collect_cert_info(
    files: &[PathBuf],
    password: Option<&str>,
) -> Result<(Vec<TestResult>, Vec<CertificateInfo>), anyhow::Error> {
    let checker = CertificateChecker::new();
    let mut all_results: Vec<TestResult> = Vec::new();
    let mut all_certs: Vec<CertificateInfo> = Vec::new();

    for file in files {
        let (certs, format) = read_certs_with_password_prompt(file, password)?;

        for (i, der) in certs.iter().enumerate() {
            let info = checker.parse_certificate(der)?;

            let cert_label = if certs.len() == 1 {
                file.display().to_string()
            } else {
                format!("{}[{}]", file.display(), i)
            };

            let status = if info.is_expired() {
                CheckStatus::Fail
            } else if info.days_until_expiry() < 30 {
                CheckStatus::Warning
            } else {
                CheckStatus::Pass
            };

            let summary = if info.is_expired() {
                "EXPIRED".to_string()
            } else {
                format!("{} days until expiry", info.days_until_expiry())
            };

            let mut result =
                TestResult::new(format!("Certificate: {}", cert_label), status, summary);

            // Basic info section
            result.details.push(DetailSection::key_value(
                Some("Certificate Details".to_string()),
                vec![
                    ("Format".to_string(), format.to_string()),
                    ("Subject".to_string(), info.subject.clone()),
                    ("Issuer".to_string(), info.issuer.clone()),
                    ("Serial".to_string(), info.serial.clone()),
                    ("Version".to_string(), format!("v{}", info.version)),
                    (
                        "Valid From".to_string(),
                        info.not_before.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                    ),
                    (
                        "Valid Until".to_string(),
                        info.not_after.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                    ),
                    (
                        "Days Until Expiry".to_string(),
                        info.days_until_expiry().to_string(),
                    ),
                    (
                        "Self-Signed".to_string(),
                        if info.is_self_signed { "Yes" } else { "No" }.to_string(),
                    ),
                    (
                        "CA Certificate".to_string(),
                        if info.is_ca { "Yes" } else { "No" }.to_string(),
                    ),
                ],
            ));

            // Key info section
            result.details.push(DetailSection::key_value(
                Some("Public Key".to_string()),
                vec![
                    ("Algorithm".to_string(), info.public_key_algorithm.clone()),
                    ("Size".to_string(), format!("{} bits", info.public_key_size)),
                    (
                        "Signature Algorithm".to_string(),
                        info.signature_algorithm.clone(),
                    ),
                ],
            ));

            // SANs
            if !info.san.is_empty() {
                result.details.push(DetailSection::list(
                    Some("Subject Alternative Names".to_string()),
                    info.san.clone(),
                ));
            }

            // Key usage
            if !info.key_usage.is_empty() {
                result.details.push(DetailSection::list(
                    Some("Key Usage".to_string()),
                    info.key_usage.clone(),
                ));
            }

            // Extended key usage
            if !info.extended_key_usage.is_empty() {
                result.details.push(DetailSection::list(
                    Some("Extended Key Usage".to_string()),
                    info.extended_key_usage.clone(),
                ));
            }

            // Thumbprint
            result.details.push(DetailSection::key_value(
                Some("Fingerprint".to_string()),
                vec![("SHA-256".to_string(), info.thumbprint.clone())],
            ));

            // Recommendations
            if info.is_expired() {
                result
                    .recommendations
                    .push("Certificate has expired and needs renewal".to_string());
            } else if info.days_until_expiry() < 30 {
                result.recommendations.push(format!(
                    "Certificate expires in {} days - consider renewal",
                    info.days_until_expiry()
                ));
            }
            if info.public_key_size < 2048 && info.public_key_algorithm.contains("rsa") {
                result
                    .recommendations
                    .push("RSA key size is below 2048 bits - consider upgrading".to_string());
            }

            all_certs.push(info);
            all_results.push(result);
        }
    }

    Ok((all_results, all_certs))
}

/// Run the `cert info` command
pub fn run_cert_info(args: &CertInfoArgs) -> Result<(), anyhow::Error> {
    let (all_results, _) = collect_cert_info(&args.files, args.password.as_deref())?;

    if args.json {
        let json = serde_json::to_string_pretty(&all_results)?;
        println!("{}", json);
    } else {
        for result in &all_results {
            print!("{}", results::format_test_result(result, true));
        }
    }

    Ok(())
}

/// Collect cert verify results without printing.
fn collect_cert_verify(
    args: &CertVerifyArgs,
) -> Result<(Vec<TestResult>, Vec<CertificateInfo>), anyhow::Error> {
    let checker = CertificateChecker::new();
    let mut all_results: Vec<TestResult> = Vec::new();
    let mut all_certs: Vec<CertificateInfo> = Vec::new();

    // Key matching mode: --cert and --key
    if let (Some(cert_path), Some(key_path)) = (&args.cert, &args.key) {
        let certs = reader::read_certificates(cert_path, None)?;
        if certs.is_empty() {
            anyhow::bail!("No certificates found in {}", cert_path.display());
        }

        // Parse the leaf cert for report data
        if let Ok(info) = checker.parse_certificate(&certs[0]) {
            all_certs.push(info);
        }

        let key_info = key_match::read_private_key(key_path)?;
        let matches = key_match::keys_match(&certs[0], &key_info)?;

        let status = if matches {
            CheckStatus::Pass
        } else {
            CheckStatus::Fail
        };

        let summary = if matches {
            "Private key matches certificate".to_string()
        } else {
            "Private key does NOT match certificate".to_string()
        };

        let mut result = TestResult::new("Key Pair Verification", status, &summary);

        result.test_steps.push(if matches {
            TestStep::pass(format!("Certificate and {} key match", key_info.key_type))
        } else {
            TestStep::fail(
                "Key mismatch",
                "The private key's public component does not match the certificate's public key",
            )
        });

        result.details.push(DetailSection::key_value(
            Some("Verification Details".to_string()),
            vec![
                ("Certificate".to_string(), cert_path.display().to_string()),
                ("Private Key".to_string(), key_path.display().to_string()),
                ("Key Type".to_string(), key_info.key_type),
                (
                    "Match".to_string(),
                    if matches { "Yes" } else { "No" }.to_string(),
                ),
            ],
        ));

        all_results.push(result);
    }

    // Chain validation mode: --chain
    if let Some(chain_path) = &args.chain {
        let certs = reader::read_certificates(chain_path, None)?;

        // Parse the leaf cert for report data
        if let Some(first) = certs.first() {
            if let Ok(info) = checker.parse_certificate(first) {
                if all_certs.is_empty() {
                    all_certs.push(info);
                }
            }
        }

        let validation = chain_verify::verify_chain(&certs, args.hostname.as_deref())?;

        let status = if validation.is_valid {
            CheckStatus::Pass
        } else {
            CheckStatus::Fail
        };

        let mut result = TestResult::new("Chain Validation", status, &validation.summary);

        for step in &validation.steps {
            result.test_steps.push(if step.passed {
                TestStep::pass(&step.description)
            } else {
                TestStep::fail(
                    &step.description,
                    step.details.as_deref().unwrap_or("Failed"),
                )
            });
        }

        result.details.push(DetailSection::text(
            Some("Note".to_string()),
            "Chain validation checks integrity (issuer chaining, signatures, time validity). \
             It does not verify trust anchoring against a root certificate store."
                .to_string(),
        ));

        if !validation.is_valid {
            result.recommendations.push(
                "Review the failed steps above and ensure certificates are correctly ordered"
                    .to_string(),
            );
        }

        all_results.push(result);
    }

    if all_results.is_empty() {
        anyhow::bail!(
            "Please specify --cert and --key for key matching, or --chain for chain validation"
        );
    }

    Ok((all_results, all_certs))
}

/// Run the `cert verify` command.
///
/// Returns `Ok(true)` if all checks passed, `Ok(false)` if any failed.
pub fn run_cert_verify(args: &CertVerifyArgs) -> Result<bool, anyhow::Error> {
    let (all_results, _) = collect_cert_verify(args)?;

    if args.json {
        let json = serde_json::to_string_pretty(&all_results)?;
        println!("{}", json);
    } else {
        for result in &all_results {
            print!("{}", results::format_test_result(result, true));
        }
    }

    let all_passed = !all_results.iter().any(|r| r.status == CheckStatus::Fail);
    Ok(all_passed)
}

/// Run the `cert convert` command
pub fn run_cert_convert(args: &CertConvertArgs) -> Result<(), anyhow::Error> {
    match &args.to {
        CertFormat::Der => {
            let input = args
                .input
                .as_ref()
                .or(args.cert.as_ref())
                .ok_or_else(|| anyhow::anyhow!("Input file required for DER conversion"))?;

            let format = reader::detect_format(input)?;
            let output = args.output.clone().unwrap_or_else(|| {
                convert::default_output_path(input, &reader::DetectedFormat::Der)
            });

            match format {
                reader::DetectedFormat::Pem => {
                    convert::pem_to_der(input, &output)?;
                    println!(
                        "  {} Converted PEM → DER: {}",
                        style("✓").green(),
                        output.display()
                    );
                }
                reader::DetectedFormat::Der => {
                    anyhow::bail!("Input is already in DER format");
                }
                reader::DetectedFormat::Pkcs12 => {
                    // Extract cert from P12 then write as DER
                    let (certs, _) =
                        read_certs_with_password_prompt(input, args.password.as_deref())?;
                    if let Some(der) = certs.first() {
                        std::fs::write(&output, der).map_err(|e| {
                            CertFileError::ConversionError {
                                message: format!("Failed to write DER: {}", e),
                            }
                        })?;
                        println!(
                            "  {} Converted PKCS#12 → DER: {}",
                            style("✓").green(),
                            output.display()
                        );
                    }
                }
            }
        }
        CertFormat::Pem => {
            let input = args
                .input
                .as_ref()
                .or(args.cert.as_ref())
                .ok_or_else(|| anyhow::anyhow!("Input file required for PEM conversion"))?;

            let format = reader::detect_format(input)?;
            let output = args.output.clone().unwrap_or_else(|| {
                convert::default_output_path(input, &reader::DetectedFormat::Pem)
            });

            match format {
                reader::DetectedFormat::Der => {
                    convert::der_to_pem(input, &output)?;
                    println!(
                        "  {} Converted DER → PEM: {}",
                        style("✓").green(),
                        output.display()
                    );
                }
                reader::DetectedFormat::Pem => {
                    anyhow::bail!("Input is already in PEM format");
                }
                reader::DetectedFormat::Pkcs12 => {
                    let pwd = resolve_pkcs12_password(input, args.password.as_deref())?;
                    convert::p12_to_pem(input, &output, Some(&pwd))?;
                    println!(
                        "  {} Converted PKCS#12 → PEM: {}",
                        style("✓").green(),
                        output.display()
                    );
                }
            }
        }
        CertFormat::P12 => {
            let cert_path = args.cert.as_ref().or(args.input.as_ref()).ok_or_else(|| {
                anyhow::anyhow!("Certificate file required for PKCS#12 conversion (use --cert)")
            })?;

            let key_path = args.key.as_ref().ok_or_else(|| {
                anyhow::anyhow!("Private key file required for PKCS#12 conversion (use --key)")
            })?;

            let output = args.output.clone().unwrap_or_else(|| {
                convert::default_output_path(cert_path, &reader::DetectedFormat::Pkcs12)
            });

            convert::pem_to_p12(cert_path, key_path, &output, args.password.as_deref())?;
            println!(
                "  {} Converted PEM → PKCS#12: {}",
                style("✓").green(),
                output.display()
            );
        }
    }

    Ok(())
}

/// Format a list of TestResults into a string for the pager.
fn format_results_for_pager(test_results: &[TestResult]) -> String {
    let mut output = String::new();
    for result in test_results {
        output.push_str(&results::format_test_result(result, true));
    }
    output
}

/// Display content in the pager (no save support for cert ops).
fn display_in_pager(header: &str, content: &str) {
    let no_save = |_: Option<String>| -> Result<Option<String>, String> { Ok(None) };
    pager::display_paged(header, content, no_save);
}

/// Generate a default filename for a cert ops HTML report.
fn generate_cert_default_filename(files: &[String]) -> String {
    let stem = if let Some(first) = files.first() {
        Path::new(first)
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "cert".to_string())
    } else {
        "cert".to_string()
    };
    let now = Local::now();
    format!("cert-report-{}-{}.html", stem, now.format("%Y-%m-%d-%H%M"))
}

/// Load theme config (same fallback as main.rs).
fn load_theme() -> config::Theme {
    config::load_default_config()
        .map(|(_, theme, _)| theme)
        .unwrap_or_default()
}

/// Run cert info interactively (prompt for files, display in pager)
pub fn run_cert_info_interactive() -> Result<(), anyhow::Error> {
    let files = interactive::prompt_cert_info_interactive()?;
    let (all_results, cert_infos) = collect_cert_info(&files, None)?;

    let header = if files.len() == 1 {
        format!("Certificate Info: {}", files[0].display())
    } else {
        format!("Certificate Info: {} files", files.len())
    };

    let source_files: Vec<String> = files.iter().map(|f| f.display().to_string()).collect();
    let output = format_results_for_pager(&all_results);

    let theme = load_theme();
    let report_data = CertOpsReportData {
        title: header.clone(),
        results: all_results,
        certificates: cert_infos,
        source_files: source_files.clone(),
    };

    let on_save = move |input: Option<String>| -> Result<Option<String>, String> {
        let default_filename = generate_cert_default_filename(&source_files);
        let path = match input {
            Some(s) if !s.trim().is_empty() => s,
            _ => default_filename,
        };
        let report = HtmlReport::new(theme.clone());
        let output_path = PathBuf::from(&path);
        report
            .generate_cert_report(&report_data, &output_path)
            .map(|_| Some(path))
            .map_err(|e| e.to_string())
    };

    pager::display_paged(&header, &output, on_save);
    Ok(())
}

/// Run cert verify interactively (prompt for mode and files, display in pager)
pub fn run_cert_verify_interactive() -> Result<(), anyhow::Error> {
    let mode = interactive::prompt_cert_verify_interactive()?;
    let (args, header, source_files) = match mode {
        CertVerifyMode::KeyMatch { cert, key } => {
            let h = format!(
                "Key Pair Verification: {} + {}",
                cert.display(),
                key.display()
            );
            let sf = vec![cert.display().to_string(), key.display().to_string()];
            (
                CertVerifyArgs {
                    cert: Some(cert),
                    key: Some(key),
                    chain: None,
                    hostname: None,
                    json: false,
                },
                h,
                sf,
            )
        }
        CertVerifyMode::ChainValidation { chain, hostname } => {
            let h = format!("Chain Validation: {}", chain.display());
            let sf = vec![chain.display().to_string()];
            (
                CertVerifyArgs {
                    cert: None,
                    key: None,
                    chain: Some(chain),
                    hostname,
                    json: false,
                },
                h,
                sf,
            )
        }
    };

    let (all_results, cert_infos) = collect_cert_verify(&args)?;
    let output = format_results_for_pager(&all_results);

    let theme = load_theme();
    let report_data = CertOpsReportData {
        title: header.clone(),
        results: all_results,
        certificates: cert_infos,
        source_files: source_files.clone(),
    };

    let on_save = move |input: Option<String>| -> Result<Option<String>, String> {
        let default_filename = generate_cert_default_filename(&source_files);
        let path = match input {
            Some(s) if !s.trim().is_empty() => s,
            _ => default_filename,
        };
        let report = HtmlReport::new(theme.clone());
        let output_path = PathBuf::from(&path);
        report
            .generate_cert_report(&report_data, &output_path)
            .map(|_| Some(path))
            .map_err(|e| e.to_string())
    };

    pager::display_paged(&header, &output, on_save);
    Ok(())
}

/// Run cert convert interactively (prompt for params, display result in pager)
pub fn run_cert_convert_interactive() -> Result<(), anyhow::Error> {
    let params = interactive::prompt_cert_convert_interactive()?;
    let input_display = params.input.display().to_string();
    let args = CertConvertArgs {
        input: Some(params.input),
        to: params.target_format,
        output: params.output,
        cert: None,
        key: params.key,
        password: params.password,
    };

    // Run conversion (prints success message to stdout)
    run_cert_convert(&args)?;

    // For convert, show a brief result in the pager with the converted file info
    let mut result = TestResult::new(
        "Certificate Conversion",
        CheckStatus::Pass,
        "Conversion complete",
    );
    result.details.push(DetailSection::key_value(
        Some("Details".to_string()),
        vec![("Input".to_string(), input_display)],
    ));
    let output = format_results_for_pager(&[result]);
    display_in_pager("Certificate Conversion", &output);
    Ok(())
}
