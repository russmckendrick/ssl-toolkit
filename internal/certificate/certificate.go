package certificate

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"
	"crypto/pkix"
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

	// Validate certificate
	if err := validateCertificate(domain, cert); err != nil {
		info.IsValidated = false
		info.ValidationError = err.Error()
	} else {
		info.IsValidated = true
	}

	return info, nil
} 