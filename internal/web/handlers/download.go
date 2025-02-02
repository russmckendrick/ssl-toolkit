package handlers

import (
	"fmt"
	"net/http"

	"github.com/russmckendrick/ssl-toolkit/internal/certificate"
	"github.com/russmckendrick/ssl-toolkit/internal/utils"
	"crypto/x509"
)

// HandleDownloadChain handles requests to download the certificate chain
func HandleDownloadChain(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "Domain parameter is required", http.StatusBadRequest)
		return
	}

	// Clean the domain
	domain, err := utils.CleanDomain(domain)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid domain: %v", err), http.StatusBadRequest)
		return
	}

	// First get the standard chain
	chain, err := certificate.GetRawCertificateChain(domain)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error getting certificate chain: %v", err), http.StatusInternalServerError)
		return
	}

	// Get the issuer name of the last certificate in our chain
	lastCert := chain[len(chain)-1]
	issuerName := lastCert.Issuer.CommonName

	// Get the root certificate from gocertifi
	fallbackChain, err := certificate.GetFallbackChain(issuerName)
	if err != nil {
		// If we can't find the root cert, just continue with what we have
		fmt.Printf("Warning: Could not find root certificate: %v\n", err)
		fallbackChain = []*x509.Certificate{}
	}

	// Merge the chains
	fullChain := certificate.MergeChains(chain, fallbackChain)

	// Convert to PEM format
	pemData := certificate.CertificateChainToPEM(fullChain)

	// Set headers for download
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-chain.pem"`, domain))
	w.Write(pemData)
} 