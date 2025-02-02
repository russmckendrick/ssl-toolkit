package dns

import (
	"fmt"
	"github.com/fatih/color"
)

func displayRecords(records DNSRecords) {
	if len(records.A) > 0 {
		fmt.Println("\n  A Records:")
		for _, r := range records.A {
			fmt.Printf("    - %s\n", r)
		}
	}
	if len(records.AAAA) > 0 {
		fmt.Println("\n  AAAA Records:")
		for _, r := range records.AAAA {
			fmt.Printf("    - %s\n", r)
		}
	}
	if len(records.MX) > 0 {
		fmt.Println("\n  MX Records:")
		for _, r := range records.MX {
			fmt.Printf("    - %s\n", r)
		}
	}
	if len(records.TXT) > 0 {
		fmt.Println("\n  TXT Records:")
		for _, r := range records.TXT {
			fmt.Printf("    - %s\n", r)
		}
	}
	if len(records.CNAME) > 0 {
		fmt.Println("\n  CNAME Records:")
		for _, r := range records.CNAME {
			fmt.Printf("    - %s\n", r)
		}
	}
	if len(records.NS) > 0 {
		fmt.Println("\n  NS Records:")
		for _, r := range records.NS {
			fmt.Printf("    - %s\n", r)
		}
	}
	if len(records.CAA) > 0 {
		fmt.Println("\n  CAA Records:")
		for _, r := range records.CAA {
			fmt.Printf("    - %s\n", r)
		}
	}
	if len(records.SRV) > 0 {
		fmt.Println("\n  SRV Records:")
		for _, r := range records.SRV {
			fmt.Printf("    - %s\n", r)
		}
	}
}

func DisplayDNSInfo(info *DNSInfo) {
	bold := color.New(color.Bold)
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)

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

	// Display nameserver consistency check
	bold.Println("\n🔍 Nameserver Consistency Check:")
	if info.IsConsistent {
		green.Println("  ✅ All nameservers are consistent")
	} else {
		red.Println("  ⚠️  Inconsistencies detected between nameservers")
	}

	// Display nameserver status
	for _, ns := range info.NameserverChecks {
		bold.Printf("\n📡 Nameserver: %s\n", ns.Nameserver)
		if ns.IsConsistent {
			green.Println("  ✓ Records match canonical records")
		} else {
			red.Println("  ✗ Records differ from canonical records")
		}
	}

	// Display detailed DNS records from the first nameserver
	if len(info.NameserverChecks) > 0 {
		bold.Println("\n📋 DNS Records:")
		fmt.Printf("  (from nameserver: %s)\n", info.NameserverChecks[0].Nameserver)
		displayRecords(info.NameserverChecks[0].Records)
	}
} 