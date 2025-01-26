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

type WebResult struct {
	Domain      string
	Certificate *certificate.CertificateInfo
	Chain       []*certificate.CertificateInfo
	HPKP        *hpkp.HPKPInfo
	DNS         *dns.DNSInfo
}

func HandleHome(w http.ResponseWriter, r *http.Request) {
	t := template.Must(template.New("home").Parse(templates.HomeTemplate))
	t.Execute(w, nil)
}

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

	result := WebResult{Domain: domain}

	// Get certificate info
	certInfo, err := certificate.GetCertificateInfo(domain)
	if err == nil {
		result.Certificate = certInfo

		// Get certificate chain regardless of validation status
		chain, err := certificate.GetCertificateChain(domain)
		if err == nil {
			result.Chain = chain
		}
	}

	// Get HPKP info
	hpkpInfo, err := hpkp.CheckHPKP(domain)
	if err == nil {
		result.HPKP = hpkpInfo
	}

	// Only get DNS info if certificate is valid
	if certInfo != nil && certInfo.IsValid() {
		dnsInfo, err := dns.GetDNSInfo(domain)
		if err == nil {
			result.DNS = dnsInfo
		}
	}

	// Add template functions
	funcMap := template.FuncMap{
		"add":  func(a, b int) int { return a + b },
		"join": strings.Join,
	}

	t := template.Must(template.New("result").Funcs(funcMap).Parse(templates.ResultTemplate))
	t.Execute(w, result)
} 