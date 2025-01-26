package main

import (
	"fmt"
	"os"

	"github.com/russmckendrick/ssl-toolkit/internal/certificate"
	"github.com/russmckendrick/ssl-toolkit/internal/dns"
	"github.com/russmckendrick/ssl-toolkit/internal/hpkp"
	"github.com/russmckendrick/ssl-toolkit/internal/utils"
	"github.com/spf13/cobra"
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "ssl-checker [domain]",
		Short: "SSL Certificate Checker",
		Long:  `A tool for checking SSL certificates, certificate chains, and DNS information for domains.`,
		Args:  cobra.MinOptionalArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
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

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
} 