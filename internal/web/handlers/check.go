package handlers

import (
	"html/template"
	"net/http"
	"strings"

	"github.com/russmckendrick/ssl-toolkit/internal/certificate"
	"github.com/russmckendrick/ssl-toolkit/internal/dns"
	"github.com/russmckendrick/ssl-toolkit/internal/hpkp"
	"github.com/russmckendrick/ssl-toolkit/internal/utils"
	"github.com/russmckendrick/ssl-toolkit/internal/web/templates"
)

func HandleCheck(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	domain, err := utils.CleanDomain(domain)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Get certificate information
	certInfo, err := certificate.GetCertificateInfo(domain)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Get certificate chain
	chain, _ := certificate.GetCertificateChain(domain)

	// Get HPKP information
	hpkpInfo, _ := hpkp.CheckHPKP(domain)

	// Get DNS information
	dnsInfo, _ := dns.GetDNSInfo(domain)

	// Create template data
	data := struct {
		Domain      string
		Certificate *certificate.CertificateInfo
		Chain       []*certificate.CertificateInfo
		HPKP        *hpkp.HPKPInfo
		DNS         *dns.DNSInfo
	}{
		Domain:      domain,
		Certificate: certInfo,
		Chain:       chain,
		HPKP:        hpkpInfo,
		DNS:         dnsInfo,
	}

	// Create template with functions
	funcMap := template.FuncMap{
		"add":  func(a, b int) int { return a + b },
		"sub":  func(a, b int) int { return a - b },
		"join": strings.Join,
		"isCompleteChain": func(chain []*certificate.CertificateInfo) bool {
			if len(chain) == 0 {
				return false
			}
			lastCert := chain[len(chain)-1]
			return lastCert.Subject.CommonName == lastCert.Issuer.CommonName
		},
		"lastCert": func(chain []*certificate.CertificateInfo) *certificate.CertificateInfo {
			if len(chain) == 0 {
				return nil
			}
			return chain[len(chain)-1]
		},
	}

	tmpl := template.Must(template.New("check").Funcs(funcMap).Parse(templates.BaseTemplate))
	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
} 