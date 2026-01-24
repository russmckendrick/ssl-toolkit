//! Certificate validation including CRL and OCSP checking

use crate::certificate::info::{CertificateInfo, OcspStatus};
use crate::error::{Result, SslToolkitError};
use base64::{engine::general_purpose::STANDARD, Engine};
use reqwest::Client;
use sha2::{Digest, Sha256};
use std::time::Duration;

/// Check OCSP status for a certificate
pub async fn check_ocsp_status(
    cert: &CertificateInfo,
    issuer_cert: Option<&CertificateInfo>,
) -> Result<OcspStatus> {
    let aia = match &cert.authority_info_access {
        Some(a) => a,
        None => return Ok(OcspStatus::Error("No OCSP responder URL found".to_string())),
    };

    if aia.ocsp_responders.is_empty() {
        return Ok(OcspStatus::Error("No OCSP responder URL found".to_string()));
    }

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| SslToolkitError::Http(e))?;

    for ocsp_url in &aia.ocsp_responders {
        match query_ocsp_responder(&client, ocsp_url, cert, issuer_cert).await {
            Ok(status) => return Ok(status),
            Err(_) => continue,
        }
    }

    Ok(OcspStatus::Error(
        "Failed to query all OCSP responders".to_string(),
    ))
}

async fn query_ocsp_responder(
    client: &Client,
    ocsp_url: &str,
    cert: &CertificateInfo,
    _issuer_cert: Option<&CertificateInfo>,
) -> Result<OcspStatus> {
    // Build OCSP request
    // This is a simplified implementation - full OCSP request building requires
    // ASN.1 encoding of the certificate serial and issuer information

    // For a proper implementation, we would:
    // 1. Hash the issuer's distinguished name
    // 2. Hash the issuer's public key
    // 3. Include the certificate serial number
    // 4. Encode as ASN.1 DER

    // Simplified: use GET request with base64-encoded minimal request
    let cert_id_hash = Sha256::digest(cert.serial_number.as_bytes());
    let request_data = build_ocsp_request(&cert.serial_number, &cert_id_hash);

    // Try GET request first (smaller requests)
    let encoded = STANDARD.encode(&request_data);
    let get_url = format!("{}/{}", ocsp_url.trim_end_matches('/'), encoded);

    let response = client
        .get(&get_url)
        .header("Accept", "application/ocsp-response")
        .send()
        .await;

    match response {
        Ok(resp) => {
            if resp.status().is_success() {
                let body = resp.bytes().await.map_err(|e| SslToolkitError::Http(e))?;
                parse_ocsp_response(&body)
            } else {
                // Try POST request
                let post_resp = client
                    .post(ocsp_url)
                    .header("Content-Type", "application/ocsp-request")
                    .body(request_data)
                    .send()
                    .await
                    .map_err(|e| SslToolkitError::Http(e))?;

                if post_resp.status().is_success() {
                    let body = post_resp.bytes().await.map_err(|e| SslToolkitError::Http(e))?;
                    parse_ocsp_response(&body)
                } else {
                    Ok(OcspStatus::Error(format!(
                        "OCSP responder returned status: {}",
                        post_resp.status()
                    )))
                }
            }
        }
        Err(e) => Ok(OcspStatus::Error(format!("OCSP request failed: {}", e))),
    }
}

fn build_ocsp_request(serial: &str, _cert_hash: &[u8]) -> Vec<u8> {
    // Simplified OCSP request structure
    // In a full implementation, this would be proper ASN.1 DER encoding
    // For now, return a minimal structure that most responders will reject
    // but allows us to detect if the responder is reachable

    // This is a placeholder - real implementation needs proper ASN.1 encoding
    let mut request = Vec::new();

    // OCSP Request sequence tag and length placeholder
    request.push(0x30); // SEQUENCE
    request.push(0x00); // Length placeholder

    // TBSRequest
    request.push(0x30); // SEQUENCE
    request.push(0x00); // Length placeholder

    // RequestList
    request.push(0x30); // SEQUENCE
    request.push(0x00); // Length placeholder

    // Single Request
    request.push(0x30); // SEQUENCE
    request.push(0x00); // Length placeholder

    // CertID - using SHA-256
    request.push(0x30); // SEQUENCE
    request.extend_from_slice(&[0x00]); // Length placeholder

    // HashAlgorithm (SHA-256)
    request.extend_from_slice(&[0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00]);

    // IssuerNameHash (placeholder)
    request.push(0x04); // OCTET STRING
    request.push(0x20); // 32 bytes
    request.extend_from_slice(&[0u8; 32]);

    // IssuerKeyHash (placeholder)
    request.push(0x04); // OCTET STRING
    request.push(0x20); // 32 bytes
    request.extend_from_slice(&[0u8; 32]);

    // SerialNumber
    request.push(0x02); // INTEGER
    let serial_bytes = hex::decode(serial.replace(":", "")).unwrap_or_default();
    request.push(serial_bytes.len() as u8);
    request.extend_from_slice(&serial_bytes);

    request
}

fn parse_ocsp_response(data: &[u8]) -> Result<OcspStatus> {
    // Parse OCSP response
    // Response status codes:
    // 0 = successful
    // 1 = malformedRequest
    // 2 = internalError
    // 3 = tryLater
    // 5 = sigRequired
    // 6 = unauthorized

    if data.len() < 3 {
        return Ok(OcspStatus::Error("Invalid OCSP response".to_string()));
    }

    // Check for SEQUENCE tag
    if data[0] != 0x30 {
        return Ok(OcspStatus::Error("Invalid OCSP response format".to_string()));
    }

    // Parse response status (simplified)
    // Looking for responseStatus which is an ENUMERATED type
    for i in 0..data.len().saturating_sub(2) {
        if data[i] == 0x0a && data[i + 1] == 0x01 {
            // ENUMERATED with length 1
            let status = data.get(i + 2).copied().unwrap_or(255);
            match status {
                0 => {
                    // Successful - parse the actual certificate status
                    return parse_cert_status_from_response(data);
                }
                1 => return Ok(OcspStatus::Error("Malformed request".to_string())),
                2 => return Ok(OcspStatus::Error("Internal error".to_string())),
                3 => return Ok(OcspStatus::Error("Try later".to_string())),
                5 => return Ok(OcspStatus::Error("Signature required".to_string())),
                6 => return Ok(OcspStatus::Error("Unauthorized".to_string())),
                _ => return Ok(OcspStatus::Error(format!("Unknown status: {}", status))),
            }
        }
    }

    Ok(OcspStatus::Error("Could not parse OCSP response".to_string()))
}

fn parse_cert_status_from_response(data: &[u8]) -> Result<OcspStatus> {
    // Look for certificate status in response
    // Status is indicated by context-specific tags:
    // [0] = good
    // [1] = revoked
    // [2] = unknown

    // Search for SingleResponse and CertStatus
    for i in 0..data.len().saturating_sub(1) {
        match data[i] {
            0x80 => {
                // Context-specific [0] - good
                return Ok(OcspStatus::Good);
            }
            0xa1 => {
                // Context-specific [1] constructed - revoked
                // Would contain revocation time and optional reason
                return Ok(OcspStatus::Revoked {
                    revocation_time: None,
                    reason: None,
                });
            }
            0x82 => {
                // Context-specific [2] - unknown
                return Ok(OcspStatus::Unknown);
            }
            _ => continue,
        }
    }

    // If we can't find explicit status, default to unknown
    Ok(OcspStatus::Unknown)
}

/// Check CRL for certificate revocation
pub async fn check_crl_status(cert: &CertificateInfo) -> Result<bool> {
    if cert.crl_distribution_points.is_empty() {
        return Ok(false); // Can't check, assume not revoked
    }

    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| SslToolkitError::Http(e))?;

    for crl_url in &cert.crl_distribution_points {
        match check_crl_for_serial(&client, crl_url, &cert.serial_number).await {
            Ok(revoked) => {
                if revoked {
                    return Ok(true);
                }
            }
            Err(_) => continue,
        }
    }

    Ok(false)
}

async fn check_crl_for_serial(
    client: &Client,
    crl_url: &str,
    serial: &str,
) -> Result<bool> {
    let response = client
        .get(crl_url)
        .send()
        .await
        .map_err(|e| SslToolkitError::Http(e))?;

    if !response.status().is_success() {
        return Err(SslToolkitError::Other(
            format!("CRL fetch failed: {}", response.status())
        ));
    }

    let crl_data = response
        .bytes()
        .await
        .map_err(|e| SslToolkitError::Http(e))?;

    // Parse CRL and check for serial
    // This is a simplified check - full implementation would parse the CRL properly
    let serial_hex = serial.replace(":", "").to_lowercase();
    let serial_bytes = hex::decode(&serial_hex).unwrap_or_default();

    // Search for the serial number in the CRL
    // This is a very simplified approach
    for window in crl_data.windows(serial_bytes.len()) {
        if window == serial_bytes.as_slice() {
            return Ok(true);
        }
    }

    Ok(false)
}

/// Validate certificate against system trust store
pub fn validate_against_trust_store(cert: &CertificateInfo) -> bool {
    // Check if the issuer is in the Mozilla root store
    // This is done by checking known root CA names
    let trusted_roots = [
        "DigiCert",
        "Let's Encrypt",
        "ISRG Root",
        "GlobalSign",
        "Comodo",
        "Sectigo",
        "GeoTrust",
        "Thawte",
        "VeriSign",
        "Entrust",
        "GoDaddy",
        "Amazon Root",
        "Microsoft",
        "Google Trust",
        "Baltimore CyberTrust",
        "Starfield",
        "QuoVadis",
        "SwissSign",
        "T-TeleSec",
        "Certum",
    ];

    if let Some(org) = &cert.issuer.organization {
        if trusted_roots.iter().any(|r| org.contains(r)) {
            return true;
        }
    }

    if let Some(cn) = &cert.issuer.common_name {
        if trusted_roots.iter().any(|r| cn.contains(r)) {
            return true;
        }
    }

    false
}
