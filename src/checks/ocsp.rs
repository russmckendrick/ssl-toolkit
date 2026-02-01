//! OCSP revocation checking
//!
//! Checks certificate revocation status via OCSP stapling and direct OCSP requests.

use crate::models::{RevocationCheckMethod, RevocationInfo, RevocationStatus};
use crate::utils::OcspError;
use sha1::{Digest, Sha1};
use std::time::Duration;
use x509_parser::prelude::*;

/// Metadata extracted from an OCSP response
struct OcspResponseMeta {
    status: RevocationStatus,
    this_update: Option<String>,
    next_update: Option<String>,
}

/// OCSP checker for certificate revocation status
pub struct OcspChecker {
    timeout: Duration,
}

impl OcspChecker {
    /// Create a new OCSP checker with the given timeout
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// Check revocation using a stapled OCSP response
    pub fn check_stapled(
        &self,
        ocsp_response_bytes: &[u8],
        cert_der: &[u8],
        issuer_der: &[u8],
    ) -> Result<RevocationInfo, OcspError> {
        let meta = self.parse_response(ocsp_response_bytes, cert_der, issuer_der)?;
        Ok(RevocationInfo {
            status: meta.status,
            method: RevocationCheckMethod::OcspStapled,
            source_url: None,
            stapled: true,
            response_issuer: None,
            this_update: meta.this_update,
            next_update: meta.next_update,
            crl_entries: None,
        })
    }

    /// Check revocation by making a direct OCSP request to the responder
    pub async fn check_direct(
        &self,
        cert_der: &[u8],
        issuer_der: &[u8],
        responder_url: &str,
    ) -> Result<RevocationInfo, OcspError> {
        let request_bytes = self.build_request(cert_der, issuer_der)?;

        let client = reqwest::Client::builder()
            .timeout(self.timeout)
            .build()
            .map_err(|e| OcspError::ResponderUnreachable {
                message: e.to_string(),
            })?;

        let response = client
            .post(responder_url)
            .header("Content-Type", "application/ocsp-request")
            .body(request_bytes)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    OcspError::Timeout
                } else {
                    OcspError::ResponderUnreachable {
                        message: e.to_string(),
                    }
                }
            })?;

        if !response.status().is_success() {
            return Err(OcspError::ResponderError {
                message: format!("HTTP {}", response.status()),
            });
        }

        let body = response
            .bytes()
            .await
            .map_err(|e| OcspError::ResponseParseError {
                message: e.to_string(),
            })?;

        let meta = self.parse_response(&body, cert_der, issuer_der)?;
        Ok(RevocationInfo {
            status: meta.status,
            method: RevocationCheckMethod::OcspDirect,
            source_url: Some(responder_url.to_string()),
            stapled: false,
            response_issuer: None,
            this_update: meta.this_update,
            next_update: meta.next_update,
            crl_entries: None,
        })
    }

    /// Check revocation by downloading and checking a CRL
    pub async fn check_crl(
        &self,
        cert_der: &[u8],
        crl_url: &str,
    ) -> Result<RevocationInfo, OcspError> {
        let (_, cert) =
            X509Certificate::from_der(cert_der).map_err(|e| OcspError::RequestBuildError {
                message: format!("Failed to parse certificate: {:?}", e),
            })?;

        let serial_bytes = cert.serial.to_bytes_be();

        let client = reqwest::Client::builder()
            .timeout(self.timeout)
            .build()
            .map_err(|e| OcspError::ResponderUnreachable {
                message: e.to_string(),
            })?;

        let response = client.get(crl_url).send().await.map_err(|e| {
            if e.is_timeout() {
                OcspError::Timeout
            } else {
                OcspError::ResponderUnreachable {
                    message: e.to_string(),
                }
            }
        })?;

        if !response.status().is_success() {
            return Err(OcspError::ResponderError {
                message: format!("CRL download HTTP {}", response.status()),
            });
        }

        let crl_bytes = response
            .bytes()
            .await
            .map_err(|e| OcspError::ResponseParseError {
                message: format!("Failed to read CRL: {}", e),
            })?;

        // Parse the CRL DER
        let (_, crl) = x509_parser::revocation_list::CertificateRevocationList::from_der(
            &crl_bytes,
        )
        .map_err(|e| OcspError::ResponseParseError {
            message: format!("Failed to parse CRL: {:?}", e),
        })?;

        // Extract CRL metadata
        let crl_issuer = crl.issuer().to_string();
        let crl_last_update = crl.last_update().to_datetime().to_string();
        let crl_next_update = crl.next_update().map(|t| t.to_datetime().to_string());
        let crl_total_entries = crl.iter_revoked_certificates().count();

        // Check if our certificate's serial is in the revoked list
        for revoked in crl.iter_revoked_certificates() {
            let revoked_serial = revoked.raw_serial();
            if trim_leading_zeros(revoked_serial) == trim_leading_zeros(&serial_bytes) {
                // Found it - certificate is revoked
                let revocation_date = Some(revoked.revocation_date.to_datetime().to_string());

                // Extract reason code if present
                let reason = revoked.reason_code().map(|(_, code)| code.to_string());

                return Ok(RevocationInfo {
                    status: RevocationStatus::Revoked {
                        revocation_date,
                        reason,
                    },
                    method: RevocationCheckMethod::Crl,
                    source_url: Some(crl_url.to_string()),
                    stapled: false,
                    response_issuer: Some(crl_issuer),
                    this_update: Some(crl_last_update),
                    next_update: crl_next_update,
                    crl_entries: Some(crl_total_entries),
                });
            }
        }

        // Serial not found in CRL = not revoked
        Ok(RevocationInfo {
            status: RevocationStatus::Good,
            method: RevocationCheckMethod::Crl,
            source_url: Some(crl_url.to_string()),
            stapled: false,
            response_issuer: Some(crl_issuer),
            this_update: Some(crl_last_update),
            next_update: crl_next_update,
            crl_entries: Some(crl_total_entries),
        })
    }

    /// Build a DER-encoded OCSP request for the given certificate
    fn build_request(&self, cert_der: &[u8], issuer_der: &[u8]) -> Result<Vec<u8>, OcspError> {
        let (_, cert) =
            X509Certificate::from_der(cert_der).map_err(|e| OcspError::RequestBuildError {
                message: format!("Failed to parse certificate: {:?}", e),
            })?;

        let (_, issuer) =
            X509Certificate::from_der(issuer_der).map_err(|e| OcspError::RequestBuildError {
                message: format!("Failed to parse issuer certificate: {:?}", e),
            })?;

        // Hash issuer name (DER encoded)
        let issuer_name_hash = {
            let mut hasher = Sha1::new();
            hasher.update(issuer.subject().as_raw());
            hasher.finalize()
        };

        // Hash issuer public key (the BIT STRING content, without the tag/length)
        let issuer_key_hash = {
            let mut hasher = Sha1::new();
            hasher.update(&*issuer.public_key().subject_public_key.data);
            hasher.finalize()
        };

        // Get serial number bytes
        let serial_bytes = cert.serial.to_bytes_be();

        // Build the OCSP request manually in DER
        // OCSPRequest ::= SEQUENCE {
        //   tbsRequest TBSRequest
        // }
        // TBSRequest ::= SEQUENCE {
        //   version [0] EXPLICIT Version DEFAULT v1,
        //   requestList SEQUENCE OF Request
        // }
        // Request ::= SEQUENCE {
        //   reqCert CertID
        // }
        // CertID ::= SEQUENCE {
        //   hashAlgorithm AlgorithmIdentifier,  -- SHA-1
        //   issuerNameHash OCTET STRING,
        //   issuerKeyHash  OCTET STRING,
        //   serialNumber   CertificateSerialNumber
        // }

        // SHA-1 AlgorithmIdentifier: SEQUENCE { OID 1.3.14.3.2.26, NULL }
        let sha1_alg_id: Vec<u8> = vec![
            0x30, 0x07, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, // OID
        ];

        // CertID
        let mut cert_id_content = Vec::new();
        cert_id_content.extend_from_slice(&sha1_alg_id);
        // issuerNameHash OCTET STRING
        cert_id_content.push(0x04); // OCTET STRING tag
        cert_id_content.push(issuer_name_hash.len() as u8);
        cert_id_content.extend_from_slice(&issuer_name_hash);
        // issuerKeyHash OCTET STRING
        cert_id_content.push(0x04);
        cert_id_content.push(issuer_key_hash.len() as u8);
        cert_id_content.extend_from_slice(&issuer_key_hash);
        // serialNumber INTEGER
        cert_id_content.push(0x02); // INTEGER tag
        der_encode_length(&mut cert_id_content, serial_bytes.len());
        cert_id_content.extend_from_slice(&serial_bytes);

        // Wrap CertID in SEQUENCE
        let cert_id = der_wrap_sequence(&cert_id_content);

        // Request ::= SEQUENCE { reqCert CertID }
        let request = der_wrap_sequence(&cert_id);

        // requestList ::= SEQUENCE OF Request
        let request_list = der_wrap_sequence(&request);

        // TBSRequest ::= SEQUENCE { requestList }
        // (version is DEFAULT v1, omit)
        let tbs_request = der_wrap_sequence(&request_list);

        // OCSPRequest ::= SEQUENCE { tbsRequest }
        let ocsp_request = der_wrap_sequence(&tbs_request);

        Ok(ocsp_request)
    }

    /// Parse an OCSP response and extract the certificate status with metadata
    fn parse_response(
        &self,
        response_bytes: &[u8],
        cert_der: &[u8],
        _issuer_der: &[u8],
    ) -> Result<OcspResponseMeta, OcspError> {
        // OCSPResponse ::= SEQUENCE {
        //   responseStatus ENUMERATED,
        //   responseBytes [0] EXPLICIT ResponseBytes OPTIONAL
        // }
        let (_, outer) = parse_der(response_bytes).map_err(|e| OcspError::ResponseParseError {
            message: format!("Failed to parse OCSP response: {:?}", e),
        })?;

        let outer_seq = outer
            .as_sequence()
            .map_err(|_| OcspError::ResponseParseError {
                message: "OCSP response is not a SEQUENCE".to_string(),
            })?;

        if outer_seq.is_empty() {
            return Err(OcspError::ResponseParseError {
                message: "Empty OCSP response".to_string(),
            });
        }

        // responseStatus
        let status_val = outer_seq[0]
            .as_u32()
            .map_err(|_| OcspError::ResponseParseError {
                message: "Invalid responseStatus".to_string(),
            })?;

        // 0 = successful, 1 = malformedRequest, 2 = internalError,
        // 3 = tryLater, 5 = sigRequired, 6 = unauthorized
        if status_val != 0 {
            let status_name = match status_val {
                1 => "malformedRequest",
                2 => "internalError",
                3 => "tryLater",
                5 => "sigRequired",
                6 => "unauthorized",
                _ => "unknown",
            };
            return Ok(OcspResponseMeta {
                status: RevocationStatus::Unknown {
                    reason: format!("OCSP responder returned: {}", status_name),
                },
                this_update: None,
                next_update: None,
            });
        }

        // responseBytes [0] EXPLICIT ResponseBytes
        if outer_seq.len() < 2 {
            return Err(OcspError::ResponseParseError {
                message: "No responseBytes in successful OCSP response".to_string(),
            });
        }

        // Parse the [0] EXPLICIT wrapper
        let response_bytes_wrapper = &outer_seq[1];
        let response_bytes_content =
            response_bytes_wrapper
                .as_slice()
                .map_err(|_| OcspError::ResponseParseError {
                    message: "Failed to read responseBytes wrapper".to_string(),
                })?;

        let (_, resp_bytes_seq) =
            parse_der(response_bytes_content).map_err(|e| OcspError::ResponseParseError {
                message: format!("Failed to parse ResponseBytes: {:?}", e),
            })?;

        let resp_bytes =
            resp_bytes_seq
                .as_sequence()
                .map_err(|_| OcspError::ResponseParseError {
                    message: "ResponseBytes is not a SEQUENCE".to_string(),
                })?;

        if resp_bytes.len() < 2 {
            return Err(OcspError::ResponseParseError {
                message: "ResponseBytes missing fields".to_string(),
            });
        }

        // responseType OID (should be id-pkix-ocsp-basic 1.3.6.1.5.5.7.48.1.1)
        // response OCTET STRING containing BasicOCSPResponse
        let basic_response_bytes =
            resp_bytes[1]
                .as_slice()
                .map_err(|_| OcspError::ResponseParseError {
                    message: "Failed to read BasicOCSPResponse bytes".to_string(),
                })?;

        // BasicOCSPResponse ::= SEQUENCE {
        //   tbsResponseData ResponseData,
        //   signatureAlgorithm AlgorithmIdentifier,
        //   signature BIT STRING,
        //   certs [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
        // }
        let (_, basic_seq_obj) =
            parse_der(basic_response_bytes).map_err(|e| OcspError::ResponseParseError {
                message: format!("Failed to parse BasicOCSPResponse: {:?}", e),
            })?;

        let basic_seq = basic_seq_obj
            .as_sequence()
            .map_err(|_| OcspError::ResponseParseError {
                message: "BasicOCSPResponse is not a SEQUENCE".to_string(),
            })?;

        if basic_seq.is_empty() {
            return Err(OcspError::ResponseParseError {
                message: "Empty BasicOCSPResponse".to_string(),
            });
        }

        // ResponseData ::= SEQUENCE {
        //   version [0] EXPLICIT Version DEFAULT v1,
        //   responderID ResponderID,
        //   producedAt GeneralizedTime,
        //   responses  SEQUENCE OF SingleResponse,
        //   responseExtensions [1] EXPLICIT Extensions OPTIONAL
        // }
        let response_data =
            basic_seq[0]
                .as_sequence()
                .map_err(|_| OcspError::ResponseParseError {
                    message: "ResponseData is not a SEQUENCE".to_string(),
                })?;

        // Find the responses field (SEQUENCE OF SingleResponse)
        // It could be at index 2 or 3 depending on whether version is present
        let serial_to_match = {
            let (_, cert) =
                X509Certificate::from_der(cert_der).map_err(|e| OcspError::ResponseParseError {
                    message: format!("Failed to parse certificate: {:?}", e),
                })?;
            cert.serial.to_bytes_be()
        };

        // Iterate through ResponseData fields looking for SEQUENCE OF SingleResponse
        for item in response_data {
            if let Ok(responses) = item.as_sequence() {
                // Each element should be a SingleResponse SEQUENCE
                for single_resp in responses {
                    if let Ok(sr_seq) = single_resp.as_sequence() {
                        // SingleResponse ::= SEQUENCE {
                        //   certID CertID,
                        //   certStatus CertStatus,
                        //   thisUpdate GeneralizedTime,
                        //   nextUpdate [0] EXPLICIT GeneralizedTime OPTIONAL,
                        //   ...
                        // }
                        if sr_seq.len() >= 2 {
                            // Check if this SingleResponse matches our certificate
                            if let Ok(cert_id_seq) = sr_seq[0].as_sequence() {
                                // CertID has serialNumber as last field
                                if let Some(last) = cert_id_seq.last() {
                                    if let Ok(resp_serial) = last.as_slice() {
                                        let resp_serial_trimmed = trim_leading_zeros(resp_serial);
                                        let cert_serial_trimmed =
                                            trim_leading_zeros(&serial_to_match);

                                        if resp_serial_trimmed == cert_serial_trimmed {
                                            return self.build_ocsp_meta(&sr_seq[1], sr_seq);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // If we found a responses sequence but didn't match the serial,
                // check the first response anyway (common case: single cert)
                if let Some(first_resp) = responses.first() {
                    if let Ok(sr_seq) = first_resp.as_sequence() {
                        if sr_seq.len() >= 2 {
                            return self.build_ocsp_meta(&sr_seq[1], sr_seq);
                        }
                    }
                }
            }
        }

        Ok(OcspResponseMeta {
            status: RevocationStatus::Unknown {
                reason: "Could not find matching SingleResponse in OCSP response".to_string(),
            },
            this_update: None,
            next_update: None,
        })
    }

    /// Build OCSP response metadata from a SingleResponse
    fn build_ocsp_meta(
        &self,
        cert_status_obj: &x509_parser::der_parser::ber::BerObject,
        single_response: &[x509_parser::der_parser::ber::BerObject],
    ) -> Result<OcspResponseMeta, OcspError> {
        let status = self.parse_cert_status(cert_status_obj)?;

        // Extract thisUpdate (index 2) and nextUpdate (index 3, optional tagged [0])
        let this_update = single_response
            .get(2)
            .and_then(|obj| extract_generalized_time(obj));

        let next_update = single_response
            .get(3)
            .and_then(|obj| extract_generalized_time(obj));

        Ok(OcspResponseMeta {
            status,
            this_update,
            next_update,
        })
    }

    /// Parse a CertStatus ASN.1 value
    fn parse_cert_status(
        &self,
        cert_status: &x509_parser::der_parser::ber::BerObject,
    ) -> Result<RevocationStatus, OcspError> {
        // CertStatus ::= CHOICE {
        //   good        [0] IMPLICIT NULL,
        //   revoked     [1] IMPLICIT RevokedInfo,
        //   unknown     [2] IMPLICIT UnknownInfo
        // }
        let tag = cert_status.header.tag();

        match tag.0 {
            0 => Ok(RevocationStatus::Good),
            1 => {
                // RevokedInfo ::= SEQUENCE {
                //   revocationTime GeneralizedTime,
                //   revocationReason [0] EXPLICIT CRLReason OPTIONAL
                // }
                // Try to extract the revocation time from the content
                let revocation_date = cert_status.as_slice().ok().and_then(|bytes| {
                    // The content is a GeneralizedTime followed optionally by reason
                    // GeneralizedTime is typically ASCII like "20240101000000Z"
                    if bytes.len() >= 15 {
                        std::str::from_utf8(&bytes[..15])
                            .ok()
                            .map(|s| s.to_string())
                    } else {
                        None
                    }
                });

                Ok(RevocationStatus::Revoked {
                    revocation_date,
                    reason: None,
                })
            }
            2 => Ok(RevocationStatus::Unknown {
                reason: "Responder reported unknown status".to_string(),
            }),
            _ => Ok(RevocationStatus::Unknown {
                reason: format!("Unexpected CertStatus tag: {}", tag.0),
            }),
        }
    }
}

/// Encode a DER length
fn der_encode_length(buf: &mut Vec<u8>, len: usize) {
    if len < 128 {
        buf.push(len as u8);
    } else if len < 256 {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push((len & 0xff) as u8);
    }
}

/// Wrap content in a DER SEQUENCE
fn der_wrap_sequence(content: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    result.push(0x30); // SEQUENCE tag
    der_encode_length(&mut result, content.len());
    result.extend_from_slice(content);
    result
}

/// Trim leading zero bytes from a byte slice (for serial number comparison)
fn trim_leading_zeros(bytes: &[u8]) -> &[u8] {
    let pos = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[pos..]
}

/// Extract a GeneralizedTime string from a BER object.
/// Handles both direct GeneralizedTime values and [0] EXPLICIT wrappers.
fn extract_generalized_time(obj: &x509_parser::der_parser::ber::BerObject) -> Option<String> {
    // First try: raw content is the time string directly (GeneralizedTime)
    if let Ok(bytes) = obj.as_slice() {
        // Filter to only printable ASCII (the time string like "20260208110838Z")
        let ascii: Vec<u8> = bytes
            .iter()
            .copied()
            .filter(|b| b.is_ascii_graphic())
            .collect();
        if ascii.len() >= 14 {
            if let Ok(s) = std::str::from_utf8(&ascii) {
                return Some(format_generalized_time(s));
            }
        }
    }

    // Second try: parse as DER to unwrap any EXPLICIT tagging
    if let Ok(raw) = obj.as_slice() {
        if let Ok((_, inner)) = parse_der(raw) {
            if let Ok(inner_bytes) = inner.as_slice() {
                let ascii: Vec<u8> = inner_bytes
                    .iter()
                    .copied()
                    .filter(|b| b.is_ascii_graphic())
                    .collect();
                if ascii.len() >= 14 {
                    if let Ok(s) = std::str::from_utf8(&ascii) {
                        return Some(format_generalized_time(s));
                    }
                }
            }
        }
    }

    None
}

/// Format a GeneralizedTime string (e.g. "20260208110838Z") into a readable date
fn format_generalized_time(s: &str) -> String {
    // GeneralizedTime: YYYYMMDDHHmmSSZ or YYYYMMDDHHmmSS.fracZ
    let s = s.trim_end_matches('Z');
    if s.len() >= 14 {
        format!(
            "{}-{}-{} {}:{}:{} UTC",
            &s[0..4],
            &s[4..6],
            &s[6..8],
            &s[8..10],
            &s[10..12],
            &s[12..14]
        )
    } else {
        s.to_string()
    }
}

/// Parse a DER-encoded blob using x509-parser's der_parser
fn parse_der(
    bytes: &[u8],
) -> Result<
    (&[u8], x509_parser::der_parser::ber::BerObject<'_>),
    x509_parser::nom::Err<x509_parser::der_parser::error::BerError>,
> {
    x509_parser::der_parser::parse_der(bytes)
}
