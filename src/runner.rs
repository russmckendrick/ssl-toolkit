//! Check orchestration engine
//!
//! Extracts the check orchestration logic from the TUI app into a standalone
//! async engine that can be driven by any frontend (CLI, TUI, etc.).

use crate::checks::{
    CertificateChecker, DnsChecker, OcspChecker, SslChecker, TcpChecker, WhoisChecker,
};
use crate::config::Settings;
use crate::models::{
    CertComparison, CertificateInfo, CheckStatus, CipherSuite, DetailSection, DnsResult,
    ReportCard, RevocationCheckMethod, RevocationInfo, RevocationStatus, SslInfo, TestResult,
    TestStep,
};
use anyhow::Result;
use std::net::IpAddr;

/// Configuration for a check run
pub struct RunConfig {
    pub domain: String,
    pub target_ips: Vec<IpAddr>,
    pub port: u16,
    pub settings: Settings,
    pub skip_whois: bool,
}

/// Events emitted during check execution
pub enum CheckEvent {
    DnsStarted,
    DnsComplete(Vec<DnsResult>),
    TcpStarted {
        ip: IpAddr,
    },
    TcpComplete {
        ip: IpAddr,
        ms: f64,
    },
    SslStarted {
        ip: IpAddr,
    },
    SslComplete {
        ip: IpAddr,
    },
    CertStarted,
    CertComplete {
        days: i64,
    },
    RevocationStarted,
    RevocationComplete {
        status: String,
    },
    ComparisonStarted {
        current: usize,
        total: usize,
        ip: IpAddr,
    },
    ComparisonComplete,
    WhoisStarted,
    WhoisComplete,
    WhoisSkipped,
    Error(String),
}

/// Complete results from a check run
pub struct RunResult {
    pub report: ReportCard,
    pub ssl_info: Option<SslInfo>,
    pub cert_info: Option<CertificateInfo>,
    pub cert_comparison: CertComparison,
    pub dns_results: Vec<DnsResult>,
}

/// Run DNS resolution across all providers
pub async fn resolve_dns(
    domain: &str,
    settings: &Settings,
    on_event: &dyn Fn(CheckEvent),
) -> Result<Vec<DnsResult>> {
    on_event(CheckEvent::DnsStarted);
    let dns_checker = DnsChecker::new(settings.dns_providers.clone());
    let results = dns_checker.resolve_all(domain).await;
    on_event(CheckEvent::DnsComplete(results.clone()));
    Ok(results)
}

/// Run all checks against a configured target
pub async fn run_checks(
    config: RunConfig,
    dns_results: Vec<DnsResult>,
    on_event: &dyn Fn(CheckEvent),
) -> Result<RunResult> {
    let domain = &config.domain;
    let ip = config.target_ips[0];
    let port = config.port;

    // TCP Check
    on_event(CheckEvent::TcpStarted { ip });
    let tcp_checker = TcpChecker::new(config.settings.ssl.connect_timeout());
    let tcp_duration = tcp_checker
        .check(ip, port)
        .await
        .map_err(|e| anyhow::anyhow!("TCP connection failed: {}", e))?;
    let tcp_ms = tcp_duration.as_secs_f64() * 1000.0;
    on_event(CheckEvent::TcpComplete { ip, ms: tcp_ms });

    // SSL Check
    on_event(CheckEvent::SslStarted { ip });
    let ssl_checker = SslChecker::new(config.settings.ssl.clone());
    let ssl_info = ssl_checker
        .check(domain, ip, port)
        .await
        .map_err(|e| anyhow::anyhow!("SSL handshake failed: {}", e))?;
    on_event(CheckEvent::SslComplete { ip });

    // Certificate Check
    on_event(CheckEvent::CertStarted);
    let cert_checker = CertificateChecker::new();
    let mut cert_info = cert_checker
        .analyze(&ssl_info.certificate_chain)
        .map_err(|e| anyhow::anyhow!("Certificate analysis failed: {}", e))?;
    let days = cert_info.days_until_expiry();
    on_event(CheckEvent::CertComplete { days });

    // Revocation Check (OCSP)
    if config.settings.ssl.check_revocation {
        on_event(CheckEvent::RevocationStarted);
        let ocsp_checker = OcspChecker::new(config.settings.ssl.ocsp_timeout());

        let issuer_der = if ssl_info.certificate_chain.len() > 1 {
            Some(&ssl_info.certificate_chain[1])
        } else {
            None
        };

        let revocation_result = if !ssl_info.ocsp_response.is_empty() {
            // Try stapled OCSP response first
            if let Some(issuer) = issuer_der {
                ocsp_checker
                    .check_stapled(&ssl_info.ocsp_response, &cert_info.raw_der, issuer)
                    .ok()
            } else {
                None
            }
        } else {
            None
        };

        let revocation_result = if revocation_result.is_none() {
            // Fall back to direct OCSP request
            if let Some(ref responder_url) = cert_info.ocsp_responder_url {
                if let Some(issuer) = issuer_der {
                    match ocsp_checker
                        .check_direct(&cert_info.raw_der, issuer, responder_url)
                        .await
                    {
                        Ok(info) => Some(info),
                        Err(e) => {
                            tracing::warn!("OCSP direct check failed: {}", e);
                            Some(RevocationInfo {
                                status: RevocationStatus::Unknown {
                                    reason: format!("OCSP check failed: {}", e),
                                },
                                method: RevocationCheckMethod::OcspDirect,
                                source_url: Some(responder_url.clone()),
                                stapled: false,
                                response_issuer: None,
                                this_update: None,
                                next_update: None,
                                crl_entries: None,
                            })
                        }
                    }
                } else {
                    Some(RevocationInfo {
                        status: RevocationStatus::Unknown {
                            reason: "No issuer certificate in chain".to_string(),
                        },
                        method: RevocationCheckMethod::None,
                        source_url: Some(responder_url.clone()),
                        stapled: false,
                        response_issuer: None,
                        this_update: None,
                        next_update: None,
                        crl_entries: None,
                    })
                }
            } else if let Some(crl_url) = cert_info.crl_distribution_points.first() {
                // No OCSP responder URL — fall back to CRL check
                match ocsp_checker.check_crl(&cert_info.raw_der, crl_url).await {
                    Ok(info) => Some(info),
                    Err(e) => {
                        tracing::warn!("CRL check failed: {}", e);
                        Some(RevocationInfo {
                            status: RevocationStatus::Unknown {
                                reason: format!("CRL check failed: {}", e),
                            },
                            method: RevocationCheckMethod::Crl,
                            source_url: Some(crl_url.clone()),
                            stapled: false,
                            response_issuer: None,
                            this_update: None,
                            next_update: None,
                            crl_entries: None,
                        })
                    }
                }
            } else {
                Some(RevocationInfo {
                    status: RevocationStatus::Unknown {
                        reason: "No OCSP responder URL or CRL distribution point in certificate"
                            .to_string(),
                    },
                    method: RevocationCheckMethod::None,
                    source_url: None,
                    stapled: false,
                    response_issuer: None,
                    this_update: None,
                    next_update: None,
                    crl_entries: None,
                })
            }
        } else {
            revocation_result
        };

        if let Some(ref rev_info) = revocation_result {
            on_event(CheckEvent::RevocationComplete {
                status: rev_info.status.to_string(),
            });
        }
        cert_info.revocation = revocation_result;
    }

    // Build report card
    let mut report = ReportCard::new(domain.clone(), ip.to_string(), port);

    // DNS Test Result
    if !dns_results.is_empty() {
        let successful = dns_results.iter().filter(|r| r.is_success()).count();
        let total = dns_results.len();
        let dns_status = if successful == total {
            CheckStatus::Pass
        } else if successful > 0 {
            CheckStatus::Warning
        } else {
            CheckStatus::Fail
        };

        let dns_rows: Vec<Vec<String>> = dns_results
            .iter()
            .map(|r| {
                let status = if r.is_success() {
                    "✓ OK"
                } else {
                    "✗ Failed"
                };
                let ips = if r.addresses.is_empty() {
                    r.error.clone().unwrap_or_else(|| "-".to_string())
                } else {
                    r.addresses
                        .iter()
                        .map(|ip| ip.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                vec![
                    r.provider.clone(),
                    status.to_string(),
                    ips,
                    format!("{}ms", r.query_time.as_millis()),
                ]
            })
            .collect();

        let mut dns_test_result = TestResult::new(
            "DNS Resolution",
            dns_status,
            format!("{}/{} providers resolved successfully", successful, total),
        )
        .with_detail(DetailSection::table(
            Some("Provider Results".to_string()),
            vec![
                "Provider".to_string(),
                "Status".to_string(),
                "IP Addresses".to_string(),
                "Time".to_string(),
            ],
            dns_rows,
        ));

        for r in &dns_results {
            if r.is_success() {
                dns_test_result = dns_test_result.with_step(TestStep::pass(format!(
                    "{} resolved to {}",
                    r.provider,
                    r.addresses
                        .iter()
                        .map(|ip| ip.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            } else {
                dns_test_result = dns_test_result.with_step(TestStep::fail(
                    format!("{} resolution failed", r.provider),
                    r.error
                        .clone()
                        .unwrap_or_else(|| "Unknown error".to_string()),
                ));
            }
        }

        report.dns_result = Some(dns_test_result);
    }

    // TCP Test Result
    report.tcp_result = Some(
        TestResult::new(
            "TCP Connectivity",
            CheckStatus::Pass,
            format!("Connection to {}:{} successful ({:.1}ms)", ip, port, tcp_ms),
        )
        .with_detail(DetailSection::key_value(
            Some("Connection Details".to_string()),
            vec![
                ("Target IP".to_string(), ip.to_string()),
                ("Port".to_string(), port.to_string()),
                ("Status".to_string(), "Connected".to_string()),
                ("Latency".to_string(), format!("{:.1}ms", tcp_ms)),
            ],
        ))
        .with_step(TestStep::pass(format!(
            "TCP connection to {}:{} established",
            ip, port
        ))),
    );

    // SSL Test Result
    let ssl_status = if ssl_info.protocol.is_secure() {
        CheckStatus::Pass
    } else if ssl_info.protocol.is_deprecated() {
        CheckStatus::Warning
    } else {
        CheckStatus::Fail
    };

    let cipher = CipherSuite::from_name(&ssl_info.cipher_suite);

    let mut ssl_test_result = TestResult::new(
        "SSL/TLS Protocol",
        ssl_status,
        format!(
            "Protocol: {}, Cipher: {}",
            ssl_info.protocol, ssl_info.cipher_suite
        ),
    )
    .with_detail(DetailSection::key_value(
        Some("Protocol Information".to_string()),
        vec![
            ("Protocol".to_string(), ssl_info.protocol.to_string()),
            ("Cipher Suite".to_string(), ssl_info.cipher_suite.clone()),
            ("Key Exchange".to_string(), cipher.key_exchange.clone()),
            ("Authentication".to_string(), cipher.authentication.clone()),
            ("Encryption".to_string(), cipher.encryption.clone()),
            ("MAC".to_string(), cipher.mac.clone()),
            (
                "Secure Renegotiation".to_string(),
                if ssl_info.secure_renegotiation {
                    "Supported".to_string()
                } else {
                    "Not Supported".to_string()
                },
            ),
            (
                "OCSP Stapling".to_string(),
                if ssl_info.ocsp_stapling {
                    "Supported".to_string()
                } else {
                    "Not Supported".to_string()
                },
            ),
        ],
    ))
    .with_step(TestStep::pass("TLS handshake completed successfully"));

    if ssl_info.protocol.is_secure() {
        ssl_test_result = ssl_test_result.with_step(TestStep::pass(format!(
            "{} is a secure protocol",
            ssl_info.protocol
        )));
    } else {
        ssl_test_result = ssl_test_result.with_step(TestStep::warning(
            format!("{} is deprecated", ssl_info.protocol),
            "Consider upgrading to TLS 1.2 or TLS 1.3",
        ));
    }

    if cipher.is_secure && !cipher.has_weakness {
        ssl_test_result = ssl_test_result.with_step(TestStep::pass("Cipher suite is secure"));
    } else if cipher.has_weakness {
        ssl_test_result = ssl_test_result.with_step(TestStep::warning(
            "Cipher suite has known weaknesses",
            "Consider using a more modern cipher suite",
        ));
    }

    if ssl_status == CheckStatus::Warning {
        ssl_test_result = ssl_test_result.with_recommendation(
            "Consider upgrading to TLS 1.2 or TLS 1.3 for improved security".to_string(),
        );
    }

    report.ssl_result = Some(ssl_test_result);

    // Certificate Test Result
    let hostname_valid = cert_info.matches_hostname(domain);
    let is_revoked = matches!(
        cert_info.revocation,
        Some(RevocationInfo {
            status: RevocationStatus::Revoked { .. },
            ..
        })
    );
    let cert_status = if days < 0 || !hostname_valid || is_revoked {
        CheckStatus::Fail
    } else if days <= 30 || cert_info.is_self_signed || !ssl_info.trust_verified {
        CheckStatus::Warning
    } else {
        CheckStatus::Pass
    };

    let cert_chain = cert_checker
        .parse_chain(&ssl_info.certificate_chain)
        .unwrap_or_default();

    let mut cert_test_result = TestResult::new(
        "Certificate Validity",
        cert_status,
        if days < 0 {
            format!("Certificate EXPIRED {} days ago", -days)
        } else {
            format!("Certificate valid for {} days", days)
        },
    )
    .with_detail(DetailSection::key_value(
        Some("Certificate Information".to_string()),
        vec![
            ("Subject".to_string(), cert_info.subject.clone()),
            ("Issuer".to_string(), cert_info.issuer.clone()),
            ("Serial Number".to_string(), cert_info.serial.clone()),
            (
                "Valid From".to_string(),
                cert_info
                    .not_before
                    .format("%Y-%m-%d %H:%M:%S UTC")
                    .to_string(),
            ),
            (
                "Valid Until".to_string(),
                cert_info
                    .not_after
                    .format("%Y-%m-%d %H:%M:%S UTC")
                    .to_string(),
            ),
            (
                "Public Key".to_string(),
                format!(
                    "{} ({} bits)",
                    cert_info.public_key_algorithm, cert_info.public_key_size
                ),
            ),
            (
                "Signature Algorithm".to_string(),
                cert_info.signature_algorithm.clone(),
            ),
            (
                "Thumbprint (SHA-256)".to_string(),
                cert_info.thumbprint.clone(),
            ),
        ],
    ));

    if !cert_info.san.is_empty() {
        cert_test_result = cert_test_result.with_detail(DetailSection::list(
            Some("Subject Alternative Names".to_string()),
            cert_info.san.clone(),
        ));
    }

    if !cert_chain.is_empty() {
        cert_test_result =
            cert_test_result.with_detail(DetailSection::certificate_chain(cert_chain));
    }

    if cert_info.is_time_valid() {
        cert_test_result =
            cert_test_result.with_step(TestStep::pass("Certificate is within validity period"));
    } else if cert_info.is_expired() {
        cert_test_result = cert_test_result.with_step(TestStep::fail(
            "Certificate has expired",
            format!("Expired on {}", cert_info.not_after.format("%Y-%m-%d")),
        ));
    } else {
        cert_test_result = cert_test_result.with_step(TestStep::fail(
            "Certificate is not yet valid",
            format!("Valid from {}", cert_info.not_before.format("%Y-%m-%d")),
        ));
    }

    if cert_info.matches_hostname(domain) {
        cert_test_result = cert_test_result.with_step(TestStep::pass(format!(
            "Certificate is valid for hostname '{}'",
            domain
        )));
    } else {
        cert_test_result = cert_test_result.with_step(TestStep::fail(
            "Certificate hostname mismatch",
            format!("Certificate is not valid for '{}'", domain),
        ));
    }

    if cert_info.is_self_signed {
        cert_test_result = cert_test_result.with_step(TestStep::warning(
            "Certificate is self-signed",
            "Self-signed certificates are not trusted by browsers",
        ));
        cert_test_result = cert_test_result.with_recommendation(
            "Replace self-signed certificate with one from a trusted CA".to_string(),
        );
    } else if !ssl_info.trust_verified {
        cert_test_result = cert_test_result.with_step(TestStep::warning(
            "Certificate chain is not trusted",
            "The certificate could not be verified against known root CAs",
        ));
        cert_test_result = cert_test_result.with_recommendation(
            "Ensure the certificate chain includes all intermediate certificates from a trusted CA"
                .to_string(),
        );
    }

    // Revocation status
    if let Some(ref rev_info) = cert_info.revocation {
        cert_test_result = cert_test_result.with_detail(DetailSection::key_value(
            Some("Revocation Status".to_string()),
            {
                let mut pairs = vec![
                    ("Status".to_string(), rev_info.status.to_string()),
                    ("Check Method".to_string(), rev_info.method.to_string()),
                ];
                if let Some(ref url) = rev_info.source_url {
                    let label = match rev_info.method {
                        RevocationCheckMethod::OcspStapled | RevocationCheckMethod::OcspDirect => {
                            "OCSP Responder"
                        }
                        RevocationCheckMethod::Crl => "CRL URL",
                        RevocationCheckMethod::None => "Source",
                    };
                    pairs.push((label.to_string(), url.clone()));
                }
                if rev_info.stapled {
                    pairs.push(("OCSP Stapling".to_string(), "Yes".to_string()));
                }
                if let Some(ref issuer) = rev_info.response_issuer {
                    pairs.push(("Issued By".to_string(), issuer.clone()));
                }
                if let Some(ref this_update) = rev_info.this_update {
                    pairs.push(("Last Updated".to_string(), this_update.clone()));
                }
                if let Some(ref next_update) = rev_info.next_update {
                    pairs.push(("Next Update".to_string(), next_update.clone()));
                }
                if let Some(entries) = rev_info.crl_entries {
                    pairs.push(("Revoked Certs in CRL".to_string(), entries.to_string()));
                }
                pairs
            },
        ));

        match &rev_info.status {
            RevocationStatus::Good => {
                cert_test_result =
                    cert_test_result.with_step(TestStep::pass("Certificate is not revoked"));
            }
            RevocationStatus::Revoked {
                revocation_date,
                reason,
            } => {
                let detail = match (revocation_date, reason) {
                    (Some(date), Some(r)) => format!("Revoked on {} ({})", date, r),
                    (Some(date), None) => format!("Revoked on {}", date),
                    (None, Some(r)) => format!("Revoked ({})", r),
                    (None, None) => "Certificate has been revoked".to_string(),
                };
                cert_test_result =
                    cert_test_result.with_step(TestStep::fail("Certificate is revoked", detail));
                cert_test_result = cert_test_result.with_recommendation(
                    "Certificate has been revoked by its CA - replace immediately".to_string(),
                );
            }
            RevocationStatus::Unknown { reason } => {
                cert_test_result = cert_test_result.with_step(TestStep::warning(
                    "Revocation status unknown",
                    reason.clone(),
                ));
            }
        }

        if !ssl_info.ocsp_stapling {
            cert_test_result = cert_test_result.with_recommendation(
                "Enable OCSP stapling for faster revocation checks".to_string(),
            );
        }
    }

    if (0..=30).contains(&days) {
        cert_test_result = cert_test_result.with_recommendation(format!(
            "Certificate expires in {} days - plan renewal",
            days
        ));
    } else if days < 0 {
        cert_test_result = cert_test_result
            .with_recommendation("Certificate has expired - renew immediately".to_string());
    }

    report.certificate_result = Some(cert_test_result);

    // WHOIS Lookup
    if !config.skip_whois {
        on_event(CheckEvent::WhoisStarted);
        let whois_settings = &config.settings.whois;
        let whois_checker = WhoisChecker::new(
            std::time::Duration::from_secs(whois_settings.timeout_secs),
            whois_settings.retry_count,
            std::time::Duration::from_millis(whois_settings.backoff_base_ms),
        );

        match whois_checker.lookup(domain).await {
            Ok(whois_info) => {
                let mut whois_pairs = Vec::new();

                if let Some(ref registrar) = whois_info.registrar {
                    whois_pairs.push(("Registrar".to_string(), registrar.clone()));
                }
                if let Some(ref created) = whois_info.created {
                    whois_pairs.push(("Created".to_string(), created.clone()));
                }
                if let Some(ref expires) = whois_info.expires {
                    whois_pairs.push(("Expires".to_string(), expires.clone()));
                }
                if let Some(ref updated) = whois_info.updated {
                    whois_pairs.push(("Updated".to_string(), updated.clone()));
                }
                if !whois_info.nameservers.is_empty() {
                    whois_pairs
                        .push(("Nameservers".to_string(), whois_info.nameservers.join(", ")));
                }
                if !whois_info.status.is_empty() {
                    // Clean status strings - take just the status name before any URL
                    let clean_statuses: Vec<String> = whois_info
                        .status
                        .iter()
                        .map(|s| s.split_whitespace().next().unwrap_or(s).to_string())
                        .collect();
                    whois_pairs.push(("Status".to_string(), clean_statuses.join(", ")));
                }

                let has_data = whois_info.registrar.is_some()
                    || whois_info.expires.is_some()
                    || whois_info.created.is_some()
                    || !whois_info.nameservers.is_empty();

                let whois_status = if has_data {
                    CheckStatus::Pass
                } else {
                    CheckStatus::Warning
                };

                let summary = if let Some(ref registrar) = whois_info.registrar {
                    format!("Registered via {}", registrar)
                } else if has_data {
                    "WHOIS data retrieved".to_string()
                } else {
                    "WHOIS data retrieved (limited info)".to_string()
                };

                let mut whois_test_result = TestResult::new("WHOIS Lookup", whois_status, summary);

                if !whois_pairs.is_empty() {
                    whois_test_result = whois_test_result.with_detail(DetailSection::key_value(
                        Some("Domain Registration".to_string()),
                        whois_pairs,
                    ));
                }

                whois_test_result =
                    whois_test_result.with_step(TestStep::pass("WHOIS query completed"));

                if let Some(ref registrar) = whois_info.registrar {
                    whois_test_result = whois_test_result.with_step(TestStep::pass(format!(
                        "Domain registered with {}",
                        registrar
                    )));
                }

                if let Some(ref expires) = whois_info.expires {
                    whois_test_result = whois_test_result.with_step(TestStep::pass(format!(
                        "Domain registration expires: {}",
                        expires
                    )));
                }

                report.whois_result = Some(whois_test_result);
                on_event(CheckEvent::WhoisComplete);
            }
            Err(e) => {
                let whois_test_result = TestResult::new(
                    "WHOIS Lookup",
                    CheckStatus::Warning,
                    format!("WHOIS lookup failed: {}", e),
                )
                .with_step(TestStep::warning("WHOIS query failed", e.to_string()));

                report.whois_result = Some(whois_test_result);
                on_event(CheckEvent::WhoisComplete);
            }
        }
    } else {
        on_event(CheckEvent::WhoisSkipped);
    }

    report.calculate_grade();

    // Certificate comparison across all IPs
    let mut cert_comparison = CertComparison::new();
    cert_comparison.set_reference(
        ip,
        cert_info.thumbprint.clone(),
        cert_info.subject.clone(),
        cert_info.issuer.clone(),
        cert_info.days_until_expiry(),
        cert_info.serial.clone(),
    );

    let other_ips: Vec<IpAddr> = config
        .target_ips
        .iter()
        .filter(|&&other_ip| other_ip != ip)
        .copied()
        .collect();

    if !other_ips.is_empty() {
        for (idx, other_ip) in other_ips.iter().enumerate() {
            on_event(CheckEvent::ComparisonStarted {
                current: idx + 1,
                total: other_ips.len(),
                ip: *other_ip,
            });

            let ssl_checker = SslChecker::new(config.settings.ssl.clone());
            match ssl_checker.check(domain, *other_ip, port).await {
                Ok(other_ssl_info) => {
                    let cert_checker = CertificateChecker::new();
                    match cert_checker.analyze(&other_ssl_info.certificate_chain) {
                        Ok(other_cert_info) => {
                            let entry = cert_comparison.compare_with_reference(
                                *other_ip,
                                &other_cert_info.thumbprint,
                                &other_cert_info.subject,
                                &other_cert_info.issuer,
                                other_cert_info.days_until_expiry(),
                                &other_cert_info.serial,
                            );
                            cert_comparison.add_entry(entry);
                        }
                        Err(e) => {
                            cert_comparison.add_entry(CertComparison::error_entry(
                                *other_ip,
                                format!("Certificate analysis failed: {}", e),
                            ));
                        }
                    }
                }
                Err(e) => {
                    cert_comparison.add_entry(CertComparison::error_entry(
                        *other_ip,
                        format!("SSL handshake failed: {}", e),
                    ));
                }
            }
        }
    }

    cert_comparison.generate_summary();
    on_event(CheckEvent::ComparisonComplete);

    Ok(RunResult {
        report,
        ssl_info: Some(ssl_info),
        cert_info: Some(cert_info),
        cert_comparison,
        dns_results,
    })
}
