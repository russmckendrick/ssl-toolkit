package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
)

type IPInfo struct {
	IP           string `json:"ip"`
	Country      string `json:"country"`
	City         string `json:"city"`
	Organization string `json:"org"`
}

type IPWhoIsResponse struct {
	Success     bool   `json:"success"`
	Country     string `json:"country"`
	City        string `json:"city"`
	Connection  struct {
		Organization string `json:"org"`
	} `json:"connection"`
}

type NameserverCheck struct {
	Nameserver     string
	IPv4Addresses  []string
	IPv6Addresses  []string
	IsConsistent   bool
}

type DNSInfo struct {
	IPv4Addresses []string
	IPv6Addresses []string
	IPv4Details   []IPInfo
	IPv6Details   []IPInfo
	NameserverChecks []NameserverCheck
	IsConsistent     bool
}

func GetDNSInfo(domain string) (*DNSInfo, error) {
	info := &DNSInfo{}
	
	// Setup HTTP client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Get nameservers
	nameservers, err := net.LookupNS(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup nameservers: %w", err)
	}

	// First get the canonical records
	ipv4, err := net.LookupIP(domain)
	if err != nil {
		return nil, err
	}

	// Separate IPv4 and IPv6 addresses for canonical records
	for _, ip := range ipv4 {
		if ipv4 := ip.To4(); ipv4 != nil {
			info.IPv4Addresses = append(info.IPv4Addresses, ipv4.String())
		} else {
			info.IPv6Addresses = append(info.IPv6Addresses, ip.String())
		}
	}

	// Check each nameserver
	info.IsConsistent = true
	for _, ns := range nameservers {
		check := NameserverCheck{
			Nameserver: ns.Host,
		}

		// Create custom resolver for this nameserver
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Second * 10,
				}
				return d.DialContext(ctx, "udp", ns.Host+":53")
			},
		}

		// Lookup IPs using this nameserver
		ips, err := r.LookupIPAddr(context.Background(), domain)
		if err != nil {
			check.IsConsistent = false
			info.IsConsistent = false
			continue
		}

		// Separate IPv4 and IPv6
		for _, ip := range ips {
			if ipv4 := ip.IP.To4(); ipv4 != nil {
				check.IPv4Addresses = append(check.IPv4Addresses, ipv4.String())
			} else {
				check.IPv6Addresses = append(check.IPv6Addresses, ip.IP.String())
			}
		}

		// Check consistency
		check.IsConsistent = compareIPLists(info.IPv4Addresses, check.IPv4Addresses) &&
			compareIPLists(info.IPv6Addresses, check.IPv6Addresses)
		
		if !check.IsConsistent {
			info.IsConsistent = false
		}

		info.NameserverChecks = append(info.NameserverChecks, check)
	}

	// Get IP details for IPv4
	for _, ip := range info.IPv4Addresses {
		details, err := getIPDetails(ip, client)
		if err == nil {
			info.IPv4Details = append(info.IPv4Details, details)
		}
	}

	// Get IP details for IPv6
	for _, ip := range info.IPv6Addresses {
		details, err := getIPDetails(ip, client)
		if err == nil {
			info.IPv6Details = append(info.IPv6Details, details)
		}
	}

	return info, nil
}

func compareIPLists(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aMap := make(map[string]bool)
	for _, ip := range a {
		aMap[ip] = true
	}
	for _, ip := range b {
		if !aMap[ip] {
			return false
		}
	}
	return true
}

func getIPDetails(ip string, client *http.Client) (IPInfo, error) {
	resp, err := client.Get(fmt.Sprintf("https://ipwho.is/%s", ip))
	if err != nil {
		return IPInfo{}, err
	}
	defer resp.Body.Close()

	var whoIsResp IPWhoIsResponse
	if err := json.NewDecoder(resp.Body).Decode(&whoIsResp); err != nil {
		return IPInfo{}, err
	}

	if !whoIsResp.Success {
		return IPInfo{}, fmt.Errorf("IP lookup failed")
	}

	return IPInfo{
		IP:           ip,
		Country:      whoIsResp.Country,
		City:         whoIsResp.City,
		Organization: whoIsResp.Connection.Organization,
	}, nil
} 