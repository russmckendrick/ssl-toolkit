package certificate

import (
	"crypto/x509/pkix"
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
	} else {
		green.Println("✅ Certificate Status: Valid")
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
	case "valid":
		yellow.Println("⚠️  Trust Status: Certificate appears valid but chain verification incomplete")
	default:
		red.Println("❌ Trust Status: Certificate validation failed")
	}

	if !cert.IsValidated {
		yellow.Println("\n⚠️  Note: Full chain verification not possible")
		yellow.Printf("Reason: %s\n", cert.ValidationError)
	}
}

// Add helper function for CertificateInfo chain completeness
func isCompleteInfoChain(chain []*CertificateInfo) bool {
	if len(chain) == 0 {
		return false
	}
	lastCert := chain[len(chain)-1]
	return lastCert.Subject.CommonName == lastCert.Issuer.CommonName
}

func DisplayCertificateChain(chain []*CertificateInfo) {
	bold := color.New(color.Bold)
	if len(chain) == 0 {
		return
	}

	fmt.Println("\n🔗 Certificate Chain Structure:")
	
	// Check if chain is incomplete
	if !isCompleteInfoChain(chain) {
		lastCert := chain[len(chain)-1]
		fmt.Printf("\n⚠️  Chain is incomplete: Root certificate (%s) is not included in the server response.\n", lastCert.Issuer.CommonName)
		fmt.Printf("Use --download-chain to get the complete certificate chain including the root certificate.\n\n")
	}

	for i, cert := range chain {
		// Print the current certificate
		prefix := "└── "
		if i < len(chain)-1 {
			prefix = "├── "
		}
		indent := strings.Repeat("│   ", i)
		fmt.Printf("%s%s%s\n", indent, prefix, cert.Subject.CommonName)
		
		// Print organization if available
		if len(cert.Subject.Organization) > 0 {
			orgPrefix := "    "
			if i < len(chain)-1 {
				orgPrefix = "│   "
			}
			fmt.Printf("%s%s(%s)\n", indent, orgPrefix, strings.Join(cert.Subject.Organization, ", "))
		}
	}

	// Then display detailed information for each certificate
	for i, cert := range chain {
		fmt.Printf("\n📜 Certificate %d:\n", i+1)
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

func displayName(name pkix.Name) {
	if name.CommonName != "" {
		fmt.Printf("  CommonName: %s\n", name.CommonName)
	}
	if len(name.Organization) > 0 {
		fmt.Printf("  Organization: %s\n", strings.Join(name.Organization, ", "))
	}
	if len(name.Country) > 0 {
		fmt.Printf("  Country: %s\n", strings.Join(name.Country, ", "))
	}
	if len(name.Locality) > 0 {
		fmt.Printf("  Locality: %s\n", strings.Join(name.Locality, ", "))
	}
	if len(name.Province) > 0 {
		fmt.Printf("  Province: %s\n", strings.Join(name.Province, ", "))
	}
} 