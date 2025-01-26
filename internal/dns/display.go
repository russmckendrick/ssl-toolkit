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
		for _, ip := range info.IPv4Addresses {
			fmt.Printf("  • %s\n", ip)
		}
	}

	// Display IPv6 addresses
	if len(info.IPv6Addresses) > 0 {
		bold.Println("\n📍 IPv6 Addresses:")
		for _, ip := range info.IPv6Addresses {
			fmt.Printf("  • %s\n", ip)
		}
	}

	// Display IP information
	if len(info.IPDetails) > 0 {
		bold.Println("\n🌍 IP Information:")
		for _, ipInfo := range info.IPDetails {
			bold.Printf("\n🔍 %s:\n", ipInfo.IP)
			fmt.Printf("  🗺️  Country: %s\n", ipInfo.Country)
			fmt.Printf("  🏙️  City: %s\n", ipInfo.City)
			fmt.Printf("  🏢 Organization: %s\n", ipInfo.Organization)
		}
	}
} 