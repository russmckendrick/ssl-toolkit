package handlers

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/russmckendrick/ssl-toolkit/internal/certificate"
	"github.com/russmckendrick/ssl-toolkit/internal/dns"
	"github.com/russmckendrick/ssl-toolkit/internal/hpkp"
	"github.com/russmckendrick/ssl-toolkit/internal/utils"
	"github.com/russmckendrick/ssl-toolkit/internal/web/templates"
)

func HandleCheck(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	targetIP := r.URL.Query().Get("ip")

	var certInfo *certificate.CertificateInfo
	var err error
	var errorMessage string
	var showRetryWithoutIP bool

	if domain != "" {
		domain, err = utils.CleanDomain(domain)
		if err != nil {
			errorMessage = fmt.Sprintf("Invalid domain: %v", err)
		} else {
			// Check certificate using IP if provided
			if targetIP != "" {
				certInfo, err = certificate.GetCertificateInfoWithIP(domain, targetIP)
				if err != nil {
					errorMessage = fmt.Sprintf("Failed to check certificate at IP %s: %v", targetIP, err)
					showRetryWithoutIP = true
				}
			} else {
				certInfo, err = certificate.GetCertificateInfo(domain)
				if err != nil {
					errorMessage = fmt.Sprintf("Failed to check certificate: %v", err)
				}
			}
		}
	}

	// Create template data
	data := struct {
		Domain            string
		TargetIP          string
		Certificate       *certificate.CertificateInfo
		Chain            []*certificate.CertificateInfo
		HPKP             *hpkp.HPKPInfo
		DNS              *dns.DNSInfo
		Title            string
		ErrorMessage     string
		ShowRetryWithoutIP bool
	}{
		Domain:            domain,
		TargetIP:          targetIP,
		Certificate:       certInfo,
		Title:            "Results for " + domain,
		ErrorMessage:      errorMessage,
		ShowRetryWithoutIP: showRetryWithoutIP,
	}

	// Only fetch certificate and HPKP info if we have a valid certificate
	if certInfo != nil && err == nil {
		// Get certificate chain
		data.Chain, _ = certificate.GetCertificateChain(domain)
		// Get HPKP information
		data.HPKP, _ = hpkp.CheckHPKP(domain)
	}

	// Create template functions map
	funcMap := template.FuncMap{
		"add":            func(a, b int) int { return a + b },
		"sub":            func(a, b int) int { return a - b },
		"join":           strings.Join,
		"isCompleteChain": func(chain []*certificate.CertificateInfo) bool {
			if len(chain) == 0 {
				return false
			}
			lastCert := chain[len(chain)-1]
			return lastCert.Subject.CommonName == lastCert.Issuer.CommonName
		},
		"isSelfSigned": func(cert *certificate.CertificateInfo) bool {
			if cert == nil {
				return false
			}
			return cert.Subject.CommonName == cert.Issuer.CommonName
		},
		"daysUntil": func(t time.Time) int {
			return int(time.Until(t).Hours() / 24)
		},
		"lastCert": func(chain []*certificate.CertificateInfo) *certificate.CertificateInfo {
			if len(chain) == 0 {
				return nil
			}
			return chain[len(chain)-1]
		},
	}

	// Parse template with functions
	tmpl := template.Must(template.New("result").Funcs(funcMap).Parse(templates.ResultTemplate))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, data); err != nil {
		fmt.Printf("Template execution error: %v\n", err)
		return
	}
}

// Add new handler for DNS check
func HandleDNSCheck(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "Domain is required", http.StatusBadRequest)
		return
	}

	domain, err := utils.CleanDomain(domain)
	if err != nil {
		http.Error(w, "Invalid domain", http.StatusBadRequest)
		return
	}

	dnsInfo, err := dns.GetDNSInfo(domain)
	if err != nil {
		http.Error(w, "Failed to get DNS info", http.StatusInternalServerError)
		return
	}

	// Create template with the same functions as the main template
	funcMap := template.FuncMap{
		"add": func(a, b int) int { return a + b },
		"sub": func(a, b int) int { return a - b },
		// ... add other necessary functions ...
	}

	tmpl := template.Must(template.New("dns").Funcs(funcMap).Parse(templates.DNSSection))
	
	data := struct {
		DNS *dns.DNSInfo
	}{
		DNS: dnsInfo,
	}

	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, "Template execution failed", http.StatusInternalServerError)
		return
	}
} 