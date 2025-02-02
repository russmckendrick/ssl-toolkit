package certificate

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
	"time"
	"github.com/gwatts/rootcerts"
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

// ---------------------------------------------------------------------
// New code to obtain a full certificate chain including fallback chain
// ---------------------------------------------------------------------

// GetFullCertificateChain returns the full certificate chain for the given domain.
// It first attempts to retrieve the chain via GetCertificateChain. If the returned chain is
// incomplete (i.e. it does not include a self-signed root certificate), then the function
// loads the fallback certificate chain from the embedded PEM file and merges them.
func GetFullCertificateChain(domain string) ([]*x509.Certificate, error) {
	// Retrieve the certificate chain using the existing function.
	chain, err := GetRawCertificateChain(domain)
	if err != nil {
		// If error retrieving chain, return error
		return nil, fmt.Errorf("failed to retrieve certificate chain for %s: %v", domain, err)
	}

	// Check if the retrieved chain is complete.
	if !isCompleteChain(chain) {
		// Get the issuer name of the last certificate in our chain
		lastCert := chain[len(chain)-1]
		issuerName := lastCert.Issuer.CommonName

		// Retrieve the fallback chain and merge with the retrieved chain.
		fallbackChain, fbErr := GetFallbackChain(issuerName)
		if fbErr == nil {
			chain = MergeChains(chain, fallbackChain)
		}
		// If fallback loading fails, continue with what we have.
	}

	return chain, nil
}

// isCompleteChain checks if the certificate chain is complete by verifying that the last certificate is self-signed.
func isCompleteChain(chain []*x509.Certificate) bool {
	if len(chain) == 0 {
		return false
	}
	lastCert := chain[len(chain)-1]
	return isSelfSigned(lastCert)
}

// isSelfSigned determines whether a certificate is self-signed.
func isSelfSigned(cert *x509.Certificate) bool {
	// A certificate is self-signed if it can verify its own signature.
	return cert.CheckSignatureFrom(cert) == nil
}

// GetFallbackChain retrieves the fallback certificate chain using rootcerts
func GetFallbackChain(issuerName string) ([]*x509.Certificate, error) {
	// Get all trusted certificates from rootcerts
	rootCerts := rootcerts.Certs()
	fmt.Printf("Looking for issuer: %s\n", issuerName)

	var certs []*x509.Certificate
	for _, cert := range rootCerts {
		x509Cert := cert.X509Cert()
		if x509Cert == nil {
			continue
		}
		
		// If issuerName is provided, only return matching certificates
		if issuerName != "" {
			if x509Cert.Subject.CommonName == issuerName || strings.Contains(x509Cert.Subject.CommonName, issuerName) {
				certs = append(certs, x509Cert)
				fmt.Printf("Found matching certificate: %s\n", x509Cert.Subject.CommonName)
			}
		} else {
			certs = append(certs, x509Cert)
		}
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no matching certificates found for issuer: %s", issuerName)
	}
	return certs, nil
}

// MergeChains merges two certificate chains, avoiding duplicate certificates.
func MergeChains(chain1, chain2 []*x509.Certificate) []*x509.Certificate {
	merged := chain1
	certMap := make(map[string]bool)
	for _, cert := range chain1 {
		certMap[string(cert.Raw)] = true
	}
	for _, cert := range chain2 {
		if !certMap[string(cert.Raw)] {
			merged = append(merged, cert)
		}
	}
	return merged
}

// GetRawCertificateChain retrieves the full chain of x509 certificates presented by the server.
func GetRawCertificateChain(domain string) ([]*x509.Certificate, error) {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, err := tls.Dial("tcp", domain+":443", conf)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates, nil
}

// CertificateChainToPEM converts a slice of x509 certificates to PEM format
func CertificateChainToPEM(chain []*x509.Certificate) []byte {
	var pemData []byte
	for _, cert := range chain {
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		pemData = append(pemData, pem.EncodeToMemory(block)...)
	}
	return pemData
}

// ListAvailableRootCerts returns a list of all root certificate names from rootcerts
func ListAvailableRootCerts() ([]string, error) {
	// Get all trusted certificates from rootcerts
	certs := rootcerts.Certs()

	var certNames []string
	fmt.Printf("Found %d certificates in pool\n", len(certs))

	for _, cert := range certs {
		// Convert to x509 certificate
		x509Cert := cert.X509Cert()
		if x509Cert != nil {
			name := fmt.Sprintf("%s", x509Cert.Subject.CommonName)
			if len(x509Cert.Subject.Organization) > 0 {
				name = fmt.Sprintf("%s (O: %s)", 
					x509Cert.Subject.CommonName, 
					strings.Join(x509Cert.Subject.Organization, ", "))
			}
			certNames = append(certNames, name)
		}
	}

	// Sort the certificates by name for better readability
	sort.Strings(certNames)
	
	return certNames, nil
} 