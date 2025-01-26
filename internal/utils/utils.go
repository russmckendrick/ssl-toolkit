package utils

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"strings"

	"golang.org/x/net/idna"
)

func PromptForDomain() string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter domain name (e.g., example.com): ")
	domain, _ := reader.ReadString('\n')
	return strings.TrimSpace(domain)
}

func CleanDomain(input string) (string, error) {
	// Remove whitespace
	domain := strings.TrimSpace(input)

	// Handle URL format
	if strings.Contains(domain, "://") {
		u, err := url.Parse(domain)
		if err != nil {
			return "", fmt.Errorf("invalid URL format: %v", err)
		}
		domain = u.Hostname()
	} else {
		// Remove protocol without //
		if strings.HasPrefix(domain, "http:") {
			domain = domain[5:]
		} else if strings.HasPrefix(domain, "https:") {
			domain = domain[6:]
		}

		// Remove paths and query parameters
		domain = strings.Split(domain, "/")[0]
		domain = strings.Split(domain, "?")[0]
		domain = strings.Split(domain, "#")[0]
	}

	// Remove trailing dots
	domain = strings.TrimRight(domain, ".")

	// Basic validation
	if domain == "" || !strings.Contains(domain, ".") {
		return "", fmt.Errorf("invalid domain format")
	}

	// Remove port numbers
	domain = strings.Split(domain, ":")[0]

	// Convert to punycode if needed
	punycode, err := idna.ToASCII(domain)
	if err != nil {
		return domain, nil // Fall back to original if punycode fails
	}

	return punycode, nil
} 