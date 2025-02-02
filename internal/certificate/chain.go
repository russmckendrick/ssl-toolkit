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
	// Get the raw certificates
	rawCerts, err := GetRawCertificateChain(domain)
	if err != nil {
		return nil, err
	}

	// Convert all certificates to CertificateInfo
	chain := []*CertificateInfo{}
	for _, cert := range rawCerts {
		info := &CertificateInfo{
			Version:       cert.Version,
			SerialNumber: fmt.Sprintf("%x", cert.SerialNumber),
			Subject:      cert.Subject,
			Issuer:       cert.Issuer,
			NotBefore:    cert.NotBefore,
			NotAfter:     cert.NotAfter,
			SignatureAlg: cert.SignatureAlgorithm,
		}

		// Add SANs if present
		if len(cert.DNSNames) > 0 {
			info.SubjectAltNames = cert.DNSNames
		}

		chain = append(chain, info)
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