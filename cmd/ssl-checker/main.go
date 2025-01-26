package main

import (
	"fmt"
	"html/template"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/russmckendrick/ssl-toolkit/internal/certificate"
	"github.com/russmckendrick/ssl-toolkit/internal/dns"
	"github.com/russmckendrick/ssl-toolkit/internal/hpkp"
	"github.com/russmckendrick/ssl-toolkit/internal/utils"
	"github.com/spf13/cobra"
)

type WebResult struct {
	Domain      string
	Certificate *certificate.CertificateInfo
	Chain       []*certificate.CertificateInfo
	HPKP        *hpkp.HPKPInfo
	DNS         *dns.DNSInfo
}

func main() {
	var webMode bool
	var port string

	var rootCmd = &cobra.Command{
		Use:   "ssl-checker [domain]",
		Short: "SSL Certificate Checker",
		Long:  `A tool for checking SSL certificates, certificate chains, and DNS information for domains.`,
		Args:  cobra.MinimumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			if webMode {
				if len(args) > 0 {
					// If domain is provided, redirect to check page
					domain, err := utils.CleanDomain(args[0])
					if err == nil {
						// Start server in background
						go startWebServer(port)
						// Open browser with domain
						url := fmt.Sprintf("http://localhost:%s/check?domain=%s", port, domain)
						fmt.Printf("Opening %s\n", url)
						openBrowser(url)
						// Keep server running
						select {}
					}
				} else {
					startWebServer(port)
				}
				return
			}

			var domain string
			if len(args) > 0 {
				domain = args[0]
			} else {
				domain = utils.PromptForDomain()
			}

			domain, err := utils.CleanDomain(domain)
			if err != nil {
				fmt.Printf("❌ Error: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("\nChecking domain: %s\n", domain)

			// Check SSL Certificate
			certInfo, err := certificate.GetCertificateInfo(domain)
			if err != nil {
				fmt.Printf("❌ Error getting certificate: %v\n", err)
				os.Exit(1)
			}

			// Display certificate information
			certificate.DisplayCertificateInfo(certInfo)

			// Check HPKP
			hpkpInfo, err := hpkp.CheckHPKP(domain)
			if err != nil {
				fmt.Printf("❌ Error checking HPKP: %v\n", err)
			} else {
				hpkp.DisplayHPKPInfo(hpkpInfo)
			}

			// Only continue if certificate is valid
			if certInfo.IsValid() {
				// Get and display certificate chain
				chain, err := certificate.GetCertificateChain(domain)
				if err != nil {
					fmt.Printf("❌ Error getting certificate chain: %v\n", err)
				} else {
					certificate.DisplayCertificateChain(chain)
				}

				// Get and display DNS information
				dnsInfo, err := dns.GetDNSInfo(domain)
				if err != nil {
					fmt.Printf("❌ Error getting DNS information: %v\n", err)
				} else {
					dns.DisplayDNSInfo(dnsInfo)
				}
			}
		},
	}

	rootCmd.Flags().BoolVarP(&webMode, "web", "w", false, "Start in web mode")
	rootCmd.Flags().StringVarP(&port, "port", "p", "8080", "Port to run web server on")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func startWebServer(port string) {
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/check", handleCheck)

	// Get domain from command line if provided
	if len(os.Args) > 2 {
		domain := os.Args[2]
		fmt.Printf("Starting web server on http://localhost:%s/check?domain=%s\n", port, domain)
	} else {
		fmt.Printf("Starting web server on http://localhost:%s\n", port)
	}

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		fmt.Printf("Error starting server: %v\n", err)
		os.Exit(1)
	}
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	tmpl := `
<!DOCTYPE html>
<html>
<head>
    <title>SSL Certificate Checker</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head>
<body class="bg-gray-100 p-8">
    <div class="max-w-2xl mx-auto">
        <h1 class="text-3xl font-bold mb-8">SSL Certificate Checker 🔒</h1>
        <form action="/check" method="GET" class="mb-8">
            <div class="flex gap-4">
                <input type="text" name="domain" placeholder="Enter domain (e.g., example.com)" 
                    class="flex-1 p-2 border rounded">
                <button type="submit" class="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600">
                    Check Certificate
                </button>
            </div>
        </form>
    </div>
</body>
</html>
`
	t := template.Must(template.New("home").Parse(tmpl))
	t.Execute(w, nil)
}

func handleCheck(w http.ResponseWriter, r *http.Request) {
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
	}

	// Get HPKP info
	hpkpInfo, err := hpkp.CheckHPKP(domain)
	if err == nil {
		result.HPKP = hpkpInfo
	}

	// If certificate is valid, get chain and DNS info
	if certInfo != nil && certInfo.IsValid() {
		chain, err := certificate.GetCertificateChain(domain)
		if err == nil {
			result.Chain = chain
		}

		dnsInfo, err := dns.GetDNSInfo(domain)
		if err == nil {
			result.DNS = dnsInfo
		}
	}

	tmpl := `
<!DOCTYPE html>
<html>
<head>
    <title>SSL Certificate Check Results - {{.Domain}}</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head>
<body class="bg-gray-100 p-8">
    <div class="max-w-4xl mx-auto">
        <div class="flex justify-between items-center mb-8">
            <h1 class="text-3xl font-bold">Results for {{.Domain}} 🔍</h1>
            <a href="/" class="bg-gray-500 text-white px-4 py-2 rounded hover:bg-gray-600">New Check</a>
        </div>

        {{if .Certificate}}
        <div class="bg-white rounded-lg shadow-md p-6 mb-6">
            <h2 class="text-2xl font-bold mb-4">🔒 SSL Certificate Information</h2>
            <div class="grid grid-cols-2 gap-4">
                <div>
                    <p class="font-semibold">Issuer:</p>
                    <p>{{.Certificate.Issuer.CommonName}}</p>
                </div>
                <div>
                    <p class="font-semibold">Valid From:</p>
                    <p>{{.Certificate.NotBefore.Format "2006-01-02 15:04:05 UTC"}}</p>
                </div>
                <div>
                    <p class="font-semibold">Valid Until:</p>
                    <p>{{.Certificate.NotAfter.Format "2006-01-02 15:04:05 UTC"}}</p>
                </div>
                <div>
                    <p class="font-semibold">Status:</p>
                    <p>{{if .Certificate.IsValid}}
                        <span class="text-green-600">✅ Valid and Trusted</span>
                    {{else}}
                        <span class="text-red-600">❌ Invalid</span>
                    {{end}}</p>
                </div>
                <div>
                    <p class="font-semibold">Trust Status:</p>
                    <p>{{if eq .Certificate.TrustStatus "trusted"}}
                        <span class="text-green-600">✅ Certificate chain is trusted</span>
                    {{else if eq .Certificate.TrustStatus "revoked"}}
                        <span class="text-red-600">🚫 Certificate has been revoked</span>
                    {{else if eq .Certificate.TrustStatus "untrusted_root"}}
                        <span class="text-yellow-600">⚠️ Chain contains untrusted root</span>
                    {{else if eq .Certificate.TrustStatus "expired"}}
                        <span class="text-red-600">📛 Certificate has expired</span>
                    {{else if eq .Certificate.TrustStatus "valid"}}
                        <span class="text-yellow-600">⚠️ Certificate appears valid but chain verification incomplete</span>
                    {{else}}
                        <span class="text-red-600">❌ Certificate validation failed</span>
                    {{end}}</p>
                </div>
                {{if .Certificate.ValidationError}}
                <div class="col-span-2">
                    <p class="font-semibold text-yellow-600">⚠️ Validation Note:</p>
                    <p class="text-gray-600">{{.Certificate.ValidationError}}</p>
                </div>
                {{end}}
            </div>
        </div>

        {{if .Certificate.SubjectAltNames}}
        <div class="bg-white rounded-lg shadow-md p-6 mb-6">
            <h3 class="text-xl font-bold mb-4">🔄 Subject Alternative Names</h3>
            <div class="grid grid-cols-1 gap-2">
                {{range .Certificate.SubjectAltNames}}
                <p class="text-gray-600">{{.}}</p>
                {{end}}
            </div>
        </div>
        {{end}}
        {{end}}

        {{if .HPKP}}
        <div class="bg-white rounded-lg shadow-md p-6 mb-6">
            <h2 class="text-2xl font-bold mb-4">📌 HPKP Information</h2>
            {{if .HPKP.HasHPKP}}
            <div class="grid grid-cols-2 gap-4">
                <div>
                    <p class="font-semibold">Status:</p>
                    <p class="text-green-600">✅ HPKP is enabled</p>
                </div>
                {{if .HPKP.ReportOnly}}
                <div>
                    <p class="font-semibold">Mode:</p>
                    <p class="text-yellow-600">⚠️ Report-Only Mode</p>
                </div>
                {{end}}
                <div>
                    <p class="font-semibold">Max Age:</p>
                    <p>{{.HPKP.MaxAge}} seconds</p>
                </div>
                {{if .HPKP.IncludeSubDomains}}
                <div>
                    <p class="font-semibold">Scope:</p>
                    <p>🔄 Includes Subdomains</p>
                </div>
                {{end}}
                {{if .HPKP.ReportURI}}
                <div class="col-span-2">
                    <p class="font-semibold">Report URI:</p>
                    <p>{{.HPKP.ReportURI}}</p>
                </div>
                {{end}}
                {{if .HPKP.Pins}}
                <div class="col-span-2">
                    <p class="font-semibold mb-2">Pin Values:</p>
                    {{range .HPKP.Pins}}
                    <p class="text-gray-600 text-sm font-mono mb-1">{{.}}</p>
                    {{end}}
                </div>
                {{end}}
            </div>
            {{else}}
            <p class="text-yellow-600">❌ HPKP is not enabled</p>
            {{end}}
        </div>
        {{end}}

        {{if .Chain}}
        <div class="bg-white rounded-lg shadow-md p-6 mb-6">
            <h2 class="text-2xl font-bold mb-4">🔗 Certificate Chain</h2>
            {{range $index, $cert := .Chain}}
            <div class="mb-6 {{if gt $index 0}}pt-6 border-t border-gray-200{{end}}">
                <h3 class="text-xl font-bold mb-4">📜 Certificate {{add $index 1}}</h3>
                <div class="grid grid-cols-2 gap-4">
                    <div>
                        <p class="font-semibold">Version:</p>
                        <p>{{.Version}}</p>
                    </div>
                    <div>
                        <p class="font-semibold">Serial Number:</p>
                        <p class="font-mono text-sm">{{.SerialNumber}}</p>
                    </div>
                    <div class="col-span-2">
                        <p class="font-semibold">Subject:</p>
                        <p>{{.Subject.CommonName}}</p>
                        {{if .Subject.Organization}}
                        <p class="text-sm text-gray-600">{{join .Subject.Organization ", "}}</p>
                        {{end}}
                    </div>
                    <div class="col-span-2">
                        <p class="font-semibold">Issuer:</p>
                        <p>{{.Issuer.CommonName}}</p>
                        {{if .Issuer.Organization}}
                        <p class="text-sm text-gray-600">{{join .Issuer.Organization ", "}}</p>
                        {{end}}
                    </div>
                    <div>
                        <p class="font-semibold">Valid From:</p>
                        <p>{{.NotBefore.Format "2006-01-02 15:04:05 UTC"}}</p>
                    </div>
                    <div>
                        <p class="font-semibold">Valid Until:</p>
                        <p>{{.NotAfter.Format "2006-01-02 15:04:05 UTC"}}</p>
                    </div>
                </div>
            </div>
            {{end}}
        </div>
        {{end}}

        {{if .DNS}}
        <div class="bg-white rounded-lg shadow-md p-6">
            <h2 class="text-2xl font-bold mb-4">🌐 DNS Information</h2>
            {{if .DNS.IPv4Addresses}}
            <div class="mb-6">
                <h3 class="text-xl font-bold mb-4">📍 IPv4 Addresses</h3>
                <div class="grid grid-cols-1 gap-2">
                    {{range .DNS.IPv4Addresses}}
                    <p class="font-mono">{{.}}</p>
                    {{end}}
                </div>
            </div>
            {{end}}

            {{if .DNS.IPv6Addresses}}
            <div class="mb-6">
                <h3 class="text-xl font-bold mb-4">📍 IPv6 Addresses</h3>
                <div class="grid grid-cols-1 gap-2">
                    {{range .DNS.IPv6Addresses}}
                    <p class="font-mono">{{.}}</p>
                    {{end}}
                </div>
            </div>
            {{end}}

            {{if .DNS.IPDetails}}
            <div>
                <h3 class="text-xl font-bold mb-4">🌍 IP Information</h3>
                <div class="grid grid-cols-1 gap-6">
                    {{range .DNS.IPDetails}}
                    <div class="border-t border-gray-200 pt-4">
                        <p class="font-semibold">🔍 {{.IP}}</p>
                        <div class="grid grid-cols-2 gap-2 mt-2">
                            <p><span class="font-semibold">Country:</span> {{.Country}}</p>
                            <p><span class="font-semibold">City:</span> {{.City}}</p>
                            <p class="col-span-2"><span class="font-semibold">Organization:</span> {{.Organization}}</p>
                        </div>
                    </div>
                    {{end}}
                </div>
            </div>
            {{end}}
        </div>
        {{end}}
    </div>
</body>
</html>
`

// Add template functions
funcMap := template.FuncMap{
	"add": func(a, b int) int {
		return a + b
	},
	"join": strings.Join,
}

t := template.Must(template.New("result").Funcs(funcMap).Parse(tmpl))
t.Execute(w, result)
}

// openBrowser opens the specified URL in the default browser
func openBrowser(url string) {
	var err error

	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}

	if err != nil {
		fmt.Printf("Error opening browser: %v\n", err)
	}
} 