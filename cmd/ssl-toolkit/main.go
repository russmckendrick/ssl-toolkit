package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"

	"github.com/russmckendrick/ssl-toolkit/internal/certificate"
	"github.com/russmckendrick/ssl-toolkit/internal/dns"
	"github.com/russmckendrick/ssl-toolkit/internal/hpkp"
	"github.com/russmckendrick/ssl-toolkit/internal/utils"
	"github.com/russmckendrick/ssl-toolkit/internal/web/handlers"
	"github.com/spf13/cobra"
)

func main() {
	var webMode bool
	var port string

	var rootCmd = &cobra.Command{
		Use:   "ssl-toolkit [domain]",
		Short: "SSL Certificate Tool Kit",
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
	http.HandleFunc("/", handlers.HandleHome)
	http.HandleFunc("/check", handlers.HandleCheck)

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