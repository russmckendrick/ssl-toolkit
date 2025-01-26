package certificate

import (
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"
)

func DisplayCertificateInfo(cert *CertificateInfo) {
	bold := color.New(color.Bold)
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)
	yellow := color.New(color.FgYellow)

	fmt.Println("\n=== 🔒 SSL Certificate Information ===")
	bold.Printf("🏢 Issuer: ")
	fmt.Printf("%s\n", cert.Issuer.CommonName)
	bold.Printf("📅 Valid From: ")
	fmt.Printf("%s\n", cert.NotBefore.UTC().Format("2006-01-02 15:04:05 UTC"))
	bold.Printf("📅 Valid Until: ")
	fmt.Printf("%s\n", cert.NotAfter.UTC().Format("2006-01-02 15:04:05 UTC"))

	// Display validation status
	now := time.Now()
	isExpired := now.After(cert.NotAfter)

	if isExpired {
		red.Println("📛 Certificate Status: Expired")
	} else if cert.IsValidated {
		green.Println("✅ Certificate Status: Valid and Trusted")
	} else {
		red.Println("❌ Certificate Status: Invalid")
	}

	// Display trust status
	switch cert.TrustStatus {
	case "trusted":
		green.Println("✅ Trust Status: Certificate chain is trusted")
		if !cert.CRLChecked {
			yellow.Println("⚠️  Note: CRL verification unavailable")
		}
	case "revoked":
		red.Println("🚫 Trust Status: Certificate has been revoked")
	case "untrusted_root":
		yellow.Println("⚠️  Trust Status: Certificate chain contains untrusted root")
	case "expired":
		red.Println("📛 Trust Status: Certificate has expired")
	default:
		red.Println("❌ Trust Status: Certificate validation failed")
	}

	if !cert.IsValidated {
		yellow.Println("\n⚠️  Warning: Certificate verification failed")
		red.Printf("❌ Reason: %s\n", cert.ValidationError)
	}
}

func DisplayCertificateChain(chain []*CertificateInfo) {
	bold := color.New(color.Bold)

	fmt.Println("\n=== 🔗 Certificate Chain ===")
	for i, cert := range chain {
		bold.Printf("\n📜 Certificate %d:\n", i+1)
		bold.Printf("📌 Version: ")
		fmt.Printf("%d\n", cert.Version)
		bold.Printf("🔑 Serial Number: ")
		fmt.Printf("%s\n", cert.SerialNumber)

		bold.Println("\n👤 Subject:")
		displayName(cert.Subject)

		bold.Println("\n📝 Issuer:")
		displayName(cert.Issuer)

		bold.Println("\n⏰ Validity Period:")
		fmt.Printf("  Not Before: %s\n", cert.NotBefore.UTC().Format("2006-01-02 15:04:05 UTC"))
		fmt.Printf("  Not After: %s\n", cert.NotAfter.UTC().Format("2006-01-02 15:04:05 UTC"))

		bold.Printf("\n🔏 Signature Algorithm: ")
		fmt.Printf("%s\n", cert.SignatureAlg)

		if len(cert.SubjectAltNames) > 0 {
			bold.Println("\n🔄 Subject Alternative Names:")
			for _, san := range cert.SubjectAltNames {
				fmt.Printf("  %s\n", san)
			}
		}
	}
}

func displayName(name x509.Name) {
	if name.CommonName != "" {
		fmt.Printf("  CommonName: %s\n", name.CommonName)
	}
	if name.Organization != nil {
		fmt.Printf("  Organization: %s\n", strings.Join(name.Organization, ", "))
	}
	if name.Country != nil {
		fmt.Printf("  Country: %s\n", strings.Join(name.Country, ", "))
	}
	if name.Locality != nil {
		fmt.Printf("  Locality: %s\n", strings.Join(name.Locality, ", "))
	}
	if name.Province != nil {
		fmt.Printf("  Province: %s\n", strings.Join(name.Province, ", "))
	}
} 