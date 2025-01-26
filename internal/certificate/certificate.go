package certificate

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"strings"
	"time"
)

type CertificateInfo struct {
	Version            int
	SerialNumber      string
	Subject           pkix.Name
	Issuer            pkix.Name
	NotBefore         time.Time
	NotAfter          time.Time
	SignatureAlg      x509.SignatureAlgorithm
	SubjectAltNames   []string
	IsValidated       bool
	ValidationError   string
	TrustStatus       string
	CRLChecked        bool
	CRLError          string
}

func (c *CertificateInfo) IsValid() bool {
	now := time.Now()
	return c.IsValidated && 
		   now.After(c.NotBefore) && 
		   now.Before(c.NotAfter) && 
		   c.TrustStatus == "trusted"
}

func GetCertificateInfo(domain string) (*CertificateInfo, error) {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", domain+":443", conf)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	cert := conn.ConnectionState().PeerCertificates[0]
	
	info := &CertificateInfo{
		Version:       cert.Version,
		SerialNumber: fmt.Sprintf("%x", cert.SerialNumber),
		Subject:      cert.Subject,
		Issuer:       cert.Issuer,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		SignatureAlg: cert.SignatureAlgorithm,
	}

	// First check if the certificate is within its validity period
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		info.IsValidated = false
		info.TrustStatus = "expired"
		info.ValidationError = "certificate is not within its validity period"
		return info, nil
	}

	// Then validate the certificate chain
	if err := validateCertificate(domain, cert); err != nil {
		info.IsValidated = false
		info.ValidationError = err.Error()

		// Check specific error types
		switch {
		case strings.Contains(err.Error(), "certificate has expired"):
			info.TrustStatus = "expired"
		case strings.Contains(err.Error(), "certificate is revoked"):
			info.TrustStatus = "revoked"
		case strings.Contains(err.Error(), "self signed"):
			info.TrustStatus = "untrusted_root"
		default:
			info.TrustStatus = "valid" // Changed from "invalid" since the cert might be valid even if we can't verify it
		}
	} else {
		info.IsValidated = true
		info.TrustStatus = "trusted"
	}

	// Add Subject Alternative Names if present
	if len(cert.DNSNames) > 0 {
		info.SubjectAltNames = cert.DNSNames
	}

	return info, nil
} 