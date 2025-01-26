package hpkp

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type HPKPInfo struct {
	HasHPKP          bool
	MaxAge           int64
	IncludeSubDomains bool
	ReportURI        string
	Pins             []string
	ReportOnly       bool
}

func CheckHPKP(domain string) (*HPKPInfo, error) {
	info := &HPKPInfo{}
	
	// Create custom transport to skip certificate verification
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second,
	}

	resp, err := client.Get(fmt.Sprintf("https://%s", domain))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check for HPKP headers
	headers := []string{"Public-Key-Pins", "Public-Key-Pins-Report-Only"}
	for _, header := range headers {
		if pinning := resp.Header.Get(header); pinning != "" {
			info.HasHPKP = true
			info.ReportOnly = header == "Public-Key-Pins-Report-Only"
			
			// Parse the header
			parts := strings.Split(pinning, ";")
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if strings.HasPrefix(part, "pin-") {
					pin := strings.SplitN(part, "=", 2)
					if len(pin) == 2 {
						info.Pins = append(info.Pins, strings.Trim(pin[1], "\""))
					}
				} else if strings.HasPrefix(part, "max-age=") {
					maxAge := strings.SplitN(part, "=", 2)
					if len(maxAge) == 2 {
						info.MaxAge, _ = strconv.ParseInt(maxAge[1], 10, 64)
					}
				} else if part == "includeSubDomains" {
					info.IncludeSubDomains = true
				} else if strings.HasPrefix(part, "report-uri=") {
					reportURI := strings.SplitN(part, "=", 2)
					if len(reportURI) == 2 {
						info.ReportURI = strings.Trim(reportURI[1], "\"")
					}
				}
			}
			break
		}
	}

	return info, nil
} 