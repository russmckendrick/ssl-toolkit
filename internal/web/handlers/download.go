package handlers

import (
	"fmt"
	"net/http"

	"github.com/russmckendrick/ssl-toolkit/internal/certificate"
	"github.com/russmckendrick/ssl-toolkit/internal/utils"
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

	fmt.Printf("\n=== Downloading certificate chain for %s ===\n", domain)

	// Get the standard chain
	chain, err := certificate.GetRawCertificateChain(domain)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error getting certificate chain: %v", err), http.StatusInternalServerError)
		return
	}

	fmt.Printf("Initial chain length: %d\n", len(chain))
	for i, cert := range chain {
		fmt.Printf("Certificate %d: Subject=%s, Issuer=%s\n", 
			i+1, 
			cert.Subject.CommonName, 
			cert.Issuer.CommonName)
	}

	// Get the complete chain including root
	fullChain, err := certificate.GetFullCertificateChain(domain)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create complete certificate chain: %v", err), http.StatusInternalServerError)
		return
	}

	fmt.Printf("\nComplete chain length: %d\n", len(fullChain))
	for i, cert := range fullChain {
		fmt.Printf("Certificate %d: Subject=%s, Issuer=%s, Self-signed=%v\n", 
			i+1, 
			cert.Subject.CommonName, 
			cert.Issuer.CommonName,
			certificate.IsSelfSigned(cert))
	}

	// Convert to PEM format
	pemData := certificate.CertificateChainToPEM(fullChain)

	// Set headers for download
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-chain.pem"`, domain))
	
	// Write the data
	bytesWritten, err := w.Write(pemData)
	if err != nil {
		fmt.Printf("Error writing response: %v\n", err)
		return
	}
	fmt.Printf("\nWrote %d bytes to response\n", bytesWritten)
	fmt.Printf("=== Download complete ===\n\n")
} 