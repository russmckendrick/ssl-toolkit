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

	// ... rest of the check handler logic ...

	// Add template functions
	funcMap := template.FuncMap{
		"add":  func(a, b int) int { return a + b },
		"join": strings.Join,
	}

	t := template.Must(template.New("result").Funcs(funcMap).Parse(templates.ResultTemplate))
	t.Execute(w, result)
} 