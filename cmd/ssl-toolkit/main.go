package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"

	"github.com/pkg/browser"
	"github.com/russmckendrick/ssl-toolkit/internal/certificate"
	"github.com/russmckendrick/ssl-toolkit/internal/dns"
	"github.com/russmckendrick/ssl-toolkit/internal/hpkp"
	"github.com/russmckendrick/ssl-toolkit/internal/utils"
	"github.com/russmckendrick/ssl-toolkit/internal/web"
	"github.com/russmckendrick/ssl-toolkit/internal/web/handlers"
	"github.com/spf13/cobra"
)

func main() {
	var webMode bool
	var port string
	var downloadChain bool
	var outputFile string
	var listCerts bool
	var debug bool
	var createReminder bool
	var reminderFile string
	var targetIP string

	var rootCmd = &cobra.Command{
		Use:   "ssl-toolkit [domain]",
		Short: "SSL Certificate Tool Kit",
		Long:  `A tool for checking SSL certificates, certificate chains, and DNS information for domains.`,
		Args:  cobra.MinimumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			// If list-certs flag is set, print all available root certificates
			if listCerts {
				certs, err := certificate.ListAvailableRootCerts()
				if err != nil {
					fmt.Printf("❌ Error listing certificates: %v\n", err)
					if debug {
						fmt.Printf("Debug: %+v\n", err)
					}
					os.Exit(1)
				}
				fmt.Printf("📜 Found %d Available Root Certificates:\n\n", len(certs))
				for _, cert := range certs {
					fmt.Printf("- %s\n", cert)
				}
				return
			}

			if webMode {
				if len(args) > 0 {
					// If domain is provided, redirect to check page
					domain, err := utils.CleanDomain(args[0])
					if err == nil {
						// Start server in background
						fmt.Printf("Starting web server...\n")
						server := web.NewServer()
						server.SetupRoutes()
						fmt.Printf("Server configured, starting on %s\n", "http://localhost:8080")
						go func() {
							// Add IP parameter to URL if provided
							url := fmt.Sprintf("http://localhost:8080/check?domain=%s", domain)
							if targetIP != "" {
								url += fmt.Sprintf("&ip=%s", targetIP)
							}
							browser.OpenURL(url)
						}()
						if err := server.Start(":8080"); err != nil {
							fmt.Printf("Server error: %v\n", err)
						}
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

			// If download chain flag is set
			if downloadChain {
				chain, err := certificate.GetFullCertificateChain(domain)
				if err != nil {
					fmt.Printf("❌ Error getting certificate chain: %v\n", err)
					os.Exit(1)
				}

				// Convert chain to PEM format
				pemData := certificate.CertificateChainToPEM(chain)

				// If no output file specified, use domain name
				if outputFile == "" {
					outputFile = fmt.Sprintf("%s-chain.pem", domain)
				}

				// Write to file
				if err := os.WriteFile(outputFile, pemData, 0644); err != nil {
					fmt.Printf("❌ Error writing certificate chain: %v\n", err)
					os.Exit(1)
				}

				fmt.Printf("✅ Certificate chain saved to %s\n", outputFile)
				return
			}

			// If create-reminder flag is set
			if createReminder {
				domain, err := utils.CleanDomain(args[0])
				if err != nil {
					fmt.Printf("❌ Error: %v\n", err)
					os.Exit(1)
				}

				certInfo, err := certificate.GetCertificateInfo(domain)
				if err != nil {
					fmt.Printf("❌ Error getting certificate: %v\n", err)
					os.Exit(1)
				}

				// Generate iCal content
				icalContent := certificate.GenerateExpiryReminder(domain, certInfo.NotAfter)

				// If no reminder file specified, use domain name
				if reminderFile == "" {
					reminderFile = fmt.Sprintf("%s-cert-expiry.ics", domain)
				}

				// Write to file
				if err := os.WriteFile(reminderFile, icalContent, 0644); err != nil {
					fmt.Printf("❌ Error writing reminder file: %v\n", err)
					os.Exit(1)
				}

				fmt.Printf("✅ Certificate expiry reminder saved to %s\n", reminderFile)
				fmt.Printf("📅 Reminder set for 30 days before expiry (%s)\n", 
					certInfo.NotAfter.AddDate(0, 0, -30).Format("2006-01-02"))
				return
			}

			domain, err := utils.CleanDomain(domain)
			if err != nil {
				fmt.Printf("❌ Error: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("\nChecking domain: %s\n", domain)

			// Modify certificate check to use target IP if specified
			var certInfo *certificate.CertificateInfo
			if targetIP != "" {
				fmt.Printf("🔍 Checking certificate at IP: %s\n", targetIP)
				certInfo, err = certificate.GetCertificateInfoWithIP(domain, targetIP)
			} else {
				certInfo, err = certificate.GetCertificateInfo(domain)
			}

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
	rootCmd.Flags().BoolVarP(&downloadChain, "download-chain", "d", false, "Download the certificate chain")
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file for certificate chain (default: <domain>-chain.pem)")
	rootCmd.Flags().BoolVarP(&listCerts, "list-certs", "l", false, "List all available root certificates")
	rootCmd.Flags().BoolVarP(&debug, "debug", "v", false, "Enable verbose debug output")
	rootCmd.Flags().BoolVarP(&createReminder, "create-reminder", "r", false, "Create an iCal reminder for certificate expiry")
	rootCmd.Flags().StringVarP(&reminderFile, "reminder-file", "i", "", "Output file for iCal reminder (default: <domain>-cert-expiry.ics)")
	rootCmd.Flags().StringVarP(&targetIP, "ip", "t", "", "Target IP address to check certificate against")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func startWebServer(port string) {
	http.HandleFunc("/", handlers.HandleHome)
	http.HandleFunc("/check", handlers.HandleCheck)
	http.HandleFunc("/download-chain", handlers.HandleDownloadChain)

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