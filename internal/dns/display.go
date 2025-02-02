package dns

import (
	"fmt"
	"github.com/fatih/color"
)

func DisplayDNSInfo(info *DNSInfo) {
	bold := color.New(color.Bold)
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)

	fmt.Println("\n=== 🌐 DNS Information ===")

	// Display nameserver consistency check
	bold.Println("\n🔍 Nameserver Consistency Check:")
	if info.IsConsistent {
		green.Println("  ✅ All nameservers are consistent")
	} else {
		red.Println("  ⚠️  Inconsistencies detected between nameservers")
	}

	// Display nameserver details
	for _, ns := range info.NameserverChecks {
		bold.Printf("\n📡 Nameserver: %s\n", ns.Nameserver)
		if ns.IsConsistent {
			green.Println("  ✓ Records match canonical records")
		} else {
			red.Println("  ✗ Records differ from canonical records")
		}
		if len(ns.IPv4Addresses) > 0 {
			fmt.Println("  IPv4 Records:")
			for _, ip := range ns.IPv4Addresses {
				fmt.Printf("    - %s\n", ip)
			}
		}
		if len(ns.IPv6Addresses) > 0 {
			fmt.Println("  IPv6 Records:")
			for _, ip := range ns.IPv6Addresses {
				fmt.Printf("    - %s\n", ip)
			}
		}
	}

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