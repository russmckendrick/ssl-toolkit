package certificate

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"time"
)

func validateCertificate(domain string, cert *x509.Certificate) error {
	// Create a cert pool with system roots
	roots, err := x509.SystemCertPool()
	if err != nil {
		return fmt.Errorf("failed to load system root CA certificates: %v", err)
	}

	// Create verification options
	opts := x509.VerifyOptions{
		DNSName: domain,
		Roots:   roots,
		CurrentTime: time.Now(),
	}

	// Verify the certificate
	_, err = cert.Verify(opts)
	if err != nil {
		return err
	}

	// Check CRL if available
	if err := checkCRL(cert); err != nil {
		return fmt.Errorf("CRL check failed: %v", err)
	}

	return nil
}

func checkCRL(cert *x509.Certificate) error {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	for _, url := range cert.CRLDistributionPoints {
		resp, err := client.Get(url)
		if err != nil {
			continue // Try next CRL if this one fails
		}
		defer resp.Body.Close()

		crl, err := x509.ParseCRL(resp.Body)
		if err != nil {
			continue
		}

		// Check if the certificate is revoked
		for _, rev := range crl.TBSCertList.RevokedCertificates {
			if rev.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return fmt.Errorf("certificate is revoked")
			}
		}
	}

	return nil
} 