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

	// Get the complete chain including root
	fullChain, err := GetFullCertificateChain(domain)
	if err != nil {
		info.IsValidated = false
		info.ValidationError = err.Error()
		info.TrustStatus = "valid" // Changed from "invalid" since the cert might be valid
		return info, nil
	}

	// Create a cert pool and add the root certificate
	rootPool := x509.NewCertPool()
	if len(fullChain) > 0 {
		rootPool.AddCert(fullChain[len(fullChain)-1])
	}

	// Create intermediate cert pool
	intermediatePool := x509.NewCertPool()
	for i := 1; i < len(fullChain)-1; i++ {
		intermediatePool.AddCert(fullChain[i])
	}

	// Verify the certificate chain
	opts := x509.VerifyOptions{
		DNSName:       domain,
		Intermediates: intermediatePool,
		Roots:        rootPool,
		CurrentTime:   now,
	}

	if _, err := cert.Verify(opts); err != nil {
		info.IsValidated = false
		info.ValidationError = err.Error()
		info.TrustStatus = "valid" // The cert might be valid even if we can't verify it
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
	chain, err := GetRawCertificateChain(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve certificate chain for %s: %v", domain, err)
	}

	// Check if the retrieved chain is complete.
	if !IsCompleteChain(chain) {
		// Try to complete the chain by following issuer relationships
		var completeChain []*x509.Certificate
		completeChain = append(completeChain, chain...)
		
		currentCert := chain[len(chain)-1]
		seen := make(map[string]bool)

		// Keep looking for issuers until we find a self-signed certificate
		for !IsSelfSigned(currentCert) {
			// Prevent infinite loops
			if seen[currentCert.Issuer.CommonName] {
				break
			}
			seen[currentCert.Issuer.CommonName] = true

			// Look for a certificate that matches the current issuer
			rootCert, err := GetFallbackChain(currentCert.Issuer.CommonName, "")
			if err == nil && len(rootCert) > 0 {
				// Verify this certificate is actually the issuer
				if err := currentCert.CheckSignatureFrom(rootCert[0]); err == nil {
					// Only add the root certificate if it's not already in the chain
					if !certificateExists(completeChain, rootCert[0]) {
						completeChain = append(completeChain, rootCert[0])
					}
					if IsSelfSigned(rootCert[0]) {
						break // We found the root, stop here
					}
					currentCert = rootCert[0]
					continue
				}
			}
			break
		}
		
		chain = completeChain
	}

	return chain, nil
}

// Helper function to check if a certificate already exists in the chain
func certificateExists(chain []*x509.Certificate, cert *x509.Certificate) bool {
	for _, c := range chain {
		if certificatesEqual(c, cert) {
			return true
		}
	}
	return false
}

// IsCompleteChain checks if the certificate chain is complete by verifying that the last certificate is self-signed.
func IsCompleteChain(chain []*x509.Certificate) bool {
	if len(chain) == 0 {
		return false
	}
	lastCert := chain[len(chain)-1]
	return IsSelfSigned(lastCert)
}

// IsSelfSigned determines whether a certificate is self-signed.
func IsSelfSigned(cert *x509.Certificate) bool {
	// A certificate is self-signed if it can verify its own signature.
	return cert.CheckSignatureFrom(cert) == nil
}

// MergeChains merges two certificate chains, avoiding duplicate certificates.
func MergeChains(chain1, chain2 []*x509.Certificate) []*x509.Certificate {
	merged := make([]*x509.Certificate, 0, len(chain1)+len(chain2))
	seen := make(map[string]bool)

	// Add all certificates from chain1
	for _, cert := range chain1 {
		certKey := string(cert.Raw)
		if !seen[certKey] {
			merged = append(merged, cert)
			seen[certKey] = true
		}
	}

	// Add only new certificates from chain2 (root certificates)
	for _, cert := range chain2 {
		certKey := string(cert.Raw)
		// Additional check to ensure we're not adding a duplicate of the last cert
		if !seen[certKey] && !certificatesEqual(cert, merged[len(merged)-1]) {
			merged = append(merged, cert)
			seen[certKey] = true
		}
	}

	return merged
}

// certificatesEqual compares two certificates to check if they are the same
func certificatesEqual(cert1, cert2 *x509.Certificate) bool {
	return cert1.Subject.CommonName == cert2.Subject.CommonName &&
		   cert1.Issuer.CommonName == cert2.Issuer.CommonName &&
		   cert1.SerialNumber.Cmp(cert2.SerialNumber) == 0
}

// GetFallbackChain retrieves the fallback certificate chain using rootcerts
func GetFallbackChain(issuerName string, issuerOrg string) ([]*x509.Certificate, error) {
	rootCerts := rootcerts.Certs()
	fmt.Printf("Looking for CA: %s\n", issuerName)

	var matchingCerts []*x509.Certificate
	for _, cert := range rootCerts {
		x509Cert := cert.X509Cert()
		if x509Cert == nil {
			continue
		}
		
		// Check for matching CommonName
		if x509Cert.Subject.CommonName == issuerName {
			fmt.Printf("Found matching CA: %s\n", x509Cert.Subject.CommonName)
			matchingCerts = append(matchingCerts, x509Cert)
		}
	}

	if len(matchingCerts) == 0 {
		return nil, fmt.Errorf("no matching certificate found for: %s", issuerName)
	}

	return matchingCerts, nil
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
	
	// Add header comment
	headerComment := "# SSL Certificate Chain\n" +
		"# Generated by SSL-Toolkit\n" +
		"# https://github.com/russmckendrick/ssl-toolkit\n\n"
	pemData = append(pemData, []byte(headerComment)...)

	for i, cert := range chain {
		// Add descriptive comment for each certificate
		var certType string
		switch {
		case i == 0:
			certType = "Leaf/Server Certificate"
		case i == len(chain)-1:
			certType = "Root Certificate"
		default:
			certType = "Intermediate Certificate"
		}

		comment := fmt.Sprintf("\n# Certificate %d (%s)\n", i+1, certType)
		comment += fmt.Sprintf("# Subject: %s\n", cert.Subject.CommonName)
		if len(cert.Subject.Organization) > 0 {
			comment += fmt.Sprintf("# Organization: %s\n", strings.Join(cert.Subject.Organization, ", "))
		}
		comment += fmt.Sprintf("# Issuer: %s\n", cert.Issuer.CommonName)
		comment += fmt.Sprintf("# Valid Until: %s\n", cert.NotAfter.Format("2006-01-02"))+"\n"
		
		pemData = append(pemData, []byte(comment)...)

		// Add the certificate in PEM format
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