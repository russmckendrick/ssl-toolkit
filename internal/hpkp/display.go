package hpkp

import (
	"fmt"
	"github.com/fatih/color"
)

func DisplayHPKPInfo(info *HPKPInfo) {
	bold := color.New(color.Bold)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)

	fmt.Println("\n=== 📌 HPKP Information ===")
	if info.HasHPKP {
		green.Println("✅ HPKP is enabled")
		if info.ReportOnly {
			yellow.Println("⚠️  Note: HPKP is in report-only mode")
		}
		bold.Printf("⏱️  Max Age: ")
		fmt.Printf("%d seconds\n", info.MaxAge)
		if info.IncludeSubDomains {
			fmt.Println("🔄 Includes Subdomains")
		}
		if info.ReportURI != "" {
			bold.Printf("📝 Report URI: ")
			fmt.Printf("%s\n", info.ReportURI)
		}
		if len(info.Pins) > 0 {
			bold.Println("\n🔐 Pin Values:")
			for _, pin := range info.Pins {
				fmt.Printf("  • %s\n", pin)
			}
		}
	} else {
		yellow.Println("❌ HPKP is not enabled")
	}
} 