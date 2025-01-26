package handlers

import (
	"html/template"
	"net/http"
	"reflect"
	"strings"

	"github.com/russmckendrick/ssl-toolkit/internal/certificate"
	"github.com/russmckendrick/ssl-toolkit/internal/dns"
	"github.com/russmckendrick/ssl-toolkit/internal/hpkp"
	"github.com/russmckendrick/ssl-toolkit/internal/utils"
	"github.com/russmckendrick/ssl-toolkit/internal/web/templates"
)

type PageData struct {
	Title       string
	Domain      string
	Certificate *certificate.CertificateInfo
	Chain       []*certificate.CertificateInfo
	HPKP        *hpkp.HPKPInfo
	DNS         *dns.DNSInfo
}

func HandleHome(w http.ResponseWriter, r *http.Request) {
	data := PageData{
		Title: "SSL Certificate Checker",
	}
	t := template.Must(template.New("home").Parse(templates.HomeTemplate))
	t.Execute(w, data)
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

	result := PageData{
		Title:  "SSL Certificate Check Results - " + domain,
		Domain: domain,
	}

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

	// Get DNS info regardless of certificate status
	dnsInfo, err := dns.GetDNSInfo(domain)
	if err == nil {
		result.DNS = dnsInfo
	}

	// Add template functions
	funcMap := template.FuncMap{
		"add":  func(a, b int) int { return a + b },
		"join": strings.Join,
		"sub":  func(a, b int) int { return a - b },
		"len":  func(s interface{}) int { return reflect.ValueOf(s).Len() },
	}

	t := template.Must(template.New("result").Funcs(funcMap).Parse(templates.ResultTemplate))
	t.Execute(w, result)
} 