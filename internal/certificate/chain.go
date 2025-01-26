package certificate

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

func GetCertificateChain(domain string) ([]*CertificateInfo, error) {
	// Get the initial certificate
	cert, err := getLeafCertificate(domain)
	if err != nil {
		return nil, err
	}

	// Build the chain
	chain := []*CertificateInfo{}
	seen := make(map[string]bool)

	current := cert
	for {
		// Convert to our certificate info format
		info := &CertificateInfo{
			Version:       current.Version,
			SerialNumber: fmt.Sprintf("%x", current.SerialNumber),
			Subject:      current.Subject,
			Issuer:       current.Issuer,
			NotBefore:    current.NotBefore,
			NotAfter:     current.NotAfter,
			SignatureAlg: current.SignatureAlgorithm,
		}

		// Add SANs if present
		if len(current.DNSNames) > 0 {
			info.SubjectAltNames = current.DNSNames
		}

		chain = append(chain, info)

		// Stop if we've reached a root (self-signed) certificate
		if current.IsCA && current.Subject.String() == current.Issuer.String() {
			break
		}

		// Get the next certificate in the chain
		next, err := getIssuerCertificate(current)
		if err != nil || next == nil {
			break
		}

		// Prevent infinite loops
		fingerprint := fmt.Sprintf("%x", next.Raw)
		if seen[fingerprint] {
			break
		}
		seen[fingerprint] = true

		current = next
	}

	return chain, nil
}

func getLeafCertificate(domain string) (*x509.Certificate, error) {
	conn, err := tls.Dial("tcp", domain+":443", &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	return conn.ConnectionState().PeerCertificates[0], nil
}

func getIssuerCertificate(cert *x509.Certificate) (*x509.Certificate, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Try to get issuer certificate from AIA
	for _, aia := range cert.IssuingCertificateURL {
		resp, err := client.Get(aia)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		// Try to parse as DER
		issuer, err := x509.ParseCertificate(body)
		if err == nil {
			return issuer, nil
		}

		// Try to parse as PEM
		block, _ := pem.Decode(body)
		if block != nil {
			issuer, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				return issuer, nil
			}
		}
	}

	return nil, fmt.Errorf("could not find issuer certificate")
} 