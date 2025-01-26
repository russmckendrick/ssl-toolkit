package dns

import (
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

type DNSInfo struct {
	IPv4Addresses []string
	IPv6Addresses []string
	IPv4Details   []IPInfo
	IPv6Details   []IPInfo
}

func GetDNSInfo(domain string) (*DNSInfo, error) {
	info := &DNSInfo{}
	
	// Setup HTTP client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Get IPv4 addresses
	ipv4, err := net.LookupIP(domain)
	if err != nil {
		return nil, err
	}

	// Separate IPv4 and IPv6 addresses
	for _, ip := range ipv4 {
		if ipv4 := ip.To4(); ipv4 != nil {
			info.IPv4Addresses = append(info.IPv4Addresses, ipv4.String())
		} else {
			info.IPv6Addresses = append(info.IPv6Addresses, ip.String())
		}
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