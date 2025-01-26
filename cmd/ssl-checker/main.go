package main

import (
	"fmt"
	"html/template"
	"net/http"
	"os"

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
				startWebServer(port)
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

	fmt.Printf("Starting web server on http://localhost:%s\n", port)
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
            </div>
        </div>
        {{end}}

        <!-- Add more sections for HPKP, Chain, and DNS info -->
    </div>
</body>
</html>
`
	t := template.Must(template.New("result").Parse(tmpl))
	t.Execute(w, result)
} 