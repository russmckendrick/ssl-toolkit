//! Integration tests for the cert subcommand operations

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

fn ssl_toolkit_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ssl-toolkit"))
}

#[test]
fn test_cert_info_pem() {
    let output = Command::new(ssl_toolkit_bin())
        .args([
            "cert",
            "info",
            fixtures_dir().join("test-cert.pem").to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "cert info failed: {}", stdout);
    assert!(
        stdout.contains("test.example.com"),
        "Should contain domain name"
    );
    assert!(
        stdout.contains("Certificate Details"),
        "Should show details"
    );
}

#[test]
fn test_cert_info_der() {
    let output = Command::new(ssl_toolkit_bin())
        .args([
            "cert",
            "info",
            fixtures_dir().join("test-cert.der").to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "cert info DER failed: {}", stdout);
    assert!(stdout.contains("DER"), "Should detect DER format");
}

#[test]
fn test_cert_info_json() {
    let output = Command::new(ssl_toolkit_bin())
        .args([
            "cert",
            "info",
            fixtures_dir().join("test-cert.pem").to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("Failed to execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "cert info json failed: {}", stdout);

    // Validate it's valid JSON
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("Output should be valid JSON");
    assert!(parsed.is_array(), "JSON output should be an array");
}

#[test]
fn test_cert_info_multiple_files() {
    let output = Command::new(ssl_toolkit_bin())
        .args([
            "cert",
            "info",
            fixtures_dir().join("test-cert.pem").to_str().unwrap(),
            fixtures_dir().join("wrong-cert.pem").to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "cert info multiple failed: {}",
        stdout
    );
    assert!(
        stdout.contains("test.example.com"),
        "Should show first cert"
    );
    assert!(
        stdout.contains("wrong.example.com"),
        "Should show second cert"
    );
}

#[test]
fn test_cert_verify_matching_key() {
    let output = Command::new(ssl_toolkit_bin())
        .args([
            "cert",
            "verify",
            "--cert",
            fixtures_dir().join("test-cert.pem").to_str().unwrap(),
            "--key",
            fixtures_dir().join("test-key.pem").to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "verify matching key should pass: {}",
        stdout
    );
    assert!(stdout.contains("match"), "Should indicate keys match");
}

#[test]
fn test_cert_verify_wrong_key() {
    let output = Command::new(ssl_toolkit_bin())
        .args([
            "cert",
            "verify",
            "--cert",
            fixtures_dir().join("test-cert.pem").to_str().unwrap(),
            "--key",
            fixtures_dir().join("wrong-key.pem").to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!output.status.success(), "verify wrong key should fail");
    assert!(
        stdout.contains("NOT match") || stdout.contains("mismatch"),
        "Should indicate key mismatch: {}",
        stdout
    );
}

#[test]
fn test_cert_verify_chain() {
    let output = Command::new(ssl_toolkit_bin())
        .args([
            "cert",
            "verify",
            "--chain",
            fixtures_dir().join("chain.pem").to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "verify chain should pass: {}",
        stdout
    );
    assert!(
        stdout.contains("Chain Validation"),
        "Should show chain validation"
    );
}

#[test]
fn test_cert_verify_chain_with_hostname() {
    let output = Command::new(ssl_toolkit_bin())
        .args([
            "cert",
            "verify",
            "--chain",
            fixtures_dir().join("chain.pem").to_str().unwrap(),
            "--hostname",
            "leaf.example.com",
        ])
        .output()
        .expect("Failed to execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "verify chain+hostname should pass: {}",
        stdout
    );
}

#[test]
fn test_cert_verify_chain_wrong_hostname() {
    let output = Command::new(ssl_toolkit_bin())
        .args([
            "cert",
            "verify",
            "--chain",
            fixtures_dir().join("chain.pem").to_str().unwrap(),
            "--hostname",
            "wrong.example.com",
        ])
        .output()
        .expect("Failed to execute");

    assert!(
        !output.status.success(),
        "verify chain+wrong hostname should fail"
    );
}

#[test]
fn test_cert_convert_pem_to_der() {
    let tmp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let output_path = tmp_dir.path().join("output.der");

    let output = Command::new(ssl_toolkit_bin())
        .args([
            "cert",
            "convert",
            fixtures_dir().join("test-cert.pem").to_str().unwrap(),
            "--to",
            "der",
            "-o",
            output_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "PEM→DER conversion failed: {}",
        stdout
    );
    assert!(output_path.exists(), "DER output file should exist");

    // Verify the output is valid DER
    let der_data = std::fs::read(&output_path).unwrap();
    assert!(der_data[0] == 0x30, "DER should start with SEQUENCE tag");
}

#[test]
fn test_cert_convert_der_to_pem() {
    let tmp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let output_path = tmp_dir.path().join("output.pem");

    let output = Command::new(ssl_toolkit_bin())
        .args([
            "cert",
            "convert",
            fixtures_dir().join("test-cert.der").to_str().unwrap(),
            "--to",
            "pem",
            "-o",
            output_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "DER→PEM conversion failed: {}",
        stdout
    );
    assert!(output_path.exists(), "PEM output file should exist");

    let pem_data = std::fs::read_to_string(&output_path).unwrap();
    assert!(
        pem_data.contains("-----BEGIN CERTIFICATE-----"),
        "Should be valid PEM"
    );
}

#[test]
fn test_cert_convert_pem_to_p12() {
    let tmp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let output_path = tmp_dir.path().join("output.p12");

    let output = Command::new(ssl_toolkit_bin())
        .args([
            "cert",
            "convert",
            "--to",
            "p12",
            "--cert",
            fixtures_dir().join("test-cert.pem").to_str().unwrap(),
            "--key",
            fixtures_dir().join("test-key.pem").to_str().unwrap(),
            "-o",
            output_path.to_str().unwrap(),
            "--password",
            "testpass",
        ])
        .output()
        .expect("Failed to execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "PEM→P12 conversion failed: {}",
        stdout
    );
    assert!(output_path.exists(), "P12 output file should exist");
    assert!(
        std::fs::metadata(&output_path).unwrap().len() > 0,
        "P12 should not be empty"
    );
}

#[test]
fn test_cert_convert_p12_to_pem() {
    let tmp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let p12_path = tmp_dir.path().join("test.p12");
    let pem_path = tmp_dir.path().join("output.pem");

    // First create a P12
    let output = Command::new(ssl_toolkit_bin())
        .args([
            "cert",
            "convert",
            "--to",
            "p12",
            "--cert",
            fixtures_dir().join("test-cert.pem").to_str().unwrap(),
            "--key",
            fixtures_dir().join("test-key.pem").to_str().unwrap(),
            "-o",
            p12_path.to_str().unwrap(),
            "--password",
            "testpass",
        ])
        .output()
        .expect("Failed to execute");
    assert!(output.status.success(), "P12 creation failed");

    // Then convert back to PEM
    let output = Command::new(ssl_toolkit_bin())
        .args([
            "cert",
            "convert",
            p12_path.to_str().unwrap(),
            "--to",
            "pem",
            "-o",
            pem_path.to_str().unwrap(),
            "--password",
            "testpass",
        ])
        .output()
        .expect("Failed to execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "P12→PEM conversion failed: {}",
        stdout
    );
    assert!(pem_path.exists(), "PEM output file should exist");

    let pem_data = std::fs::read_to_string(&pem_path).unwrap();
    assert!(pem_data.contains("-----BEGIN"), "Should contain PEM blocks");
}

#[test]
fn test_existing_domain_check_unbroken() {
    // Verify the original domain check still works with no subcommand
    let output = Command::new(ssl_toolkit_bin())
        .args(["-d", "example.com", "--non-interactive", "--quiet"])
        .output()
        .expect("Failed to execute");

    // It should either succeed or fail with a network error,
    // but it should NOT fail with a CLI parsing error
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("error: unexpected argument"),
        "Existing CLI should still work: {}",
        stderr
    );
}
