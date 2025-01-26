package dns

import (
	"fmt"
	"github.com/fatih/color"
)

func DisplayDNSInfo(info *DNSInfo) {
	bold := color.New(color.Bold)

	fmt.Println("\n=== 🌐 DNS Information ===")

	// Display IPv4 addresses
	if len(info.IPv4Addresses) > 0 {
		bold.Println("\n📍 IPv4 Addresses:")
		for i, ip := range info.IPv4Addresses {
			fmt.Printf("  %s\n", ip)
			if i < len(info.IPv4Details) {
				details := info.IPv4Details[i]
				if details.Country != "" {
					fmt.Printf("    Country: %s\n", details.Country)
				}
				if details.City != "" {
					fmt.Printf("    City: %s\n", details.City)
				}
				if details.Organization != "" {
					fmt.Printf("    Organization: %s\n", details.Organization)
				}
			}
		}
	}

	// Display IPv6 addresses
	if len(info.IPv6Addresses) > 0 {
		bold.Println("\n📍 IPv6 Addresses:")
		for i, ip := range info.IPv6Addresses {
			fmt.Printf("  %s\n", ip)
			if i < len(info.IPv6Details) {
				details := info.IPv6Details[i]
				if details.Country != "" {
					fmt.Printf("    Country: %s\n", details.Country)
				}
				if details.City != "" {
					fmt.Printf("    City: %s\n", details.City)
				}
				if details.Organization != "" {
					fmt.Printf("    Organization: %s\n", details.Organization)
				}
			}
		}
	}
} 