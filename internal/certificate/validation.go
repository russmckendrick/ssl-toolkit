package certificate

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
	"github.com/gwatts/rootcerts"
)

func validateCertificate(domain string, cert *x509.Certificate) error {
	roots := rootcerts.ServerCertPool()

	opts := x509.VerifyOptions{
		DNSName: domain,
		Roots:   roots,
	}

	_, err := cert.Verify(opts)
	return err
}

func checkCRL(cert *x509.Certificate) error {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	for _, url := range cert.CRLDistributionPoints {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// Read the body into a byte slice
		crlBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		crl, err := x509.ParseCRL(crlBytes)
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