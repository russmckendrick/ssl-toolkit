package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
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

type DNSRecords struct {
	A     []string
	AAAA  []string
	MX    []string
	TXT   []string
	CNAME []string
	NS    []string
	SOA   string
	CAA   []string
	SRV   []string
	PTR   []string
}

type NameserverCheck struct {
	Nameserver     string
	IPv4Addresses  []string
	IPv6Addresses  []string
	IsConsistent   bool
	Records        DNSRecords
}

type DNSInfo struct {
	IPv4Addresses []string
	IPv6Addresses []string
	IPv4Details   []IPInfo
	IPv6Details   []IPInfo
	NameserverChecks []NameserverCheck
	IsConsistent     bool
}

func GetDNSRecords(domain string, resolver *net.Resolver) (DNSRecords, error) {
	ctx := context.Background()
	records := DNSRecords{}

	// Try AXFR transfer first
	axfrRecords := tryZoneTransfer(domain)
	if len(axfrRecords.A) > 0 {
		return axfrRecords, nil
	}

	// If AXFR fails, fall back to individual queries
	// Common subdomains to check
	subdomains := []string{
		"",           // apex
		"www",
		"mail",
		"smtp",
		"pop",
		"imap",
		"webmail",
		"remote",
		"vpn",
		"ftp",
		"files",
		"cloud",
		"cdn",
		"api",
		"dev",
		"staging",
		"test",
		"admin",
		"portal",
		"intranet",
		"extranet",
		"blog",
		"shop",
		"store",
		"m",          // mobile
		"app",
		"gateway",
		"secure",
		"autodiscover", // Exchange/O365
		"_domainkey",   // DKIM
		"_dmarc",       // DMARC
	}

	// Query each subdomain
	for _, sub := range subdomains {
		target := domain
		if sub != "" {
			target = sub + "." + domain
		}

		// A records
		if ips, err := resolver.LookupIPAddr(ctx, target); err == nil {
			for _, ip := range ips {
				if ipv4 := ip.IP.To4(); ipv4 != nil {
					records.A = append(records.A, fmt.Sprintf("%s: %s", target, ipv4.String()))
				} else {
					records.AAAA = append(records.AAAA, fmt.Sprintf("%s: %s", target, ip.IP.String()))
				}
			}
		}

		// CNAME records
		if cname, err := resolver.LookupCNAME(ctx, target); err == nil {
			records.CNAME = append(records.CNAME, fmt.Sprintf("%s → %s", target, cname))
		}
	}

	// Rest of existing record lookups...
	if mxs, err := resolver.LookupMX(ctx, domain); err == nil {
		for _, mx := range mxs {
			records.MX = append(records.MX, fmt.Sprintf("%s (priority: %d)", mx.Host, mx.Pref))
		}
	}

	// TXT records
	if txts, err := resolver.LookupTXT(ctx, domain); err == nil {
		records.TXT = txts
	}

	// NS records
	if nss, err := resolver.LookupNS(ctx, domain); err == nil {
		for _, ns := range nss {
			records.NS = append(records.NS, ns.Host)
		}
	}

	// CAA records (using miekg/dns for CAA since net package doesn't support it)
	records.CAA = lookupCAA(domain)

	// SRV records (common services)
	services := []string{"_http._tcp", "_https._tcp", "_sip._tcp", "_xmpp-server._tcp"}
	for _, service := range services {
		if _, addrs, err := resolver.LookupSRV(ctx, "", service, domain); err == nil {
			for _, srv := range addrs {
				records.SRV = append(records.SRV, 
					fmt.Sprintf("%s:%d (priority: %d, weight: %d)", 
						srv.Target, srv.Port, srv.Priority, srv.Weight))
			}
		}
	}

	return records, nil
}

func tryZoneTransfer(domain string) DNSRecords {
	records := DNSRecords{}

	// First get the nameservers
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	
	c := new(dns.Client)
	r, _, err := c.Exchange(m, "8.8.8.8:53")
	if err != nil {
		return records
	}

	// Try AXFR with each nameserver
	for _, ans := range r.Answer {
		if ns, ok := ans.(*dns.NS); ok {
			tr := new(dns.Transfer)
			m := new(dns.Msg)
			m.SetAxfr(domain)
			
			// Try the transfer
			ch, err := tr.In(m, net.JoinHostPort(ns.Ns, "53"))
			if err != nil {
				continue
			}

			for env := range ch {
				if env.Error != nil {
					continue
				}
				
				// Process records from successful transfer
				for _, rr := range env.RR {
					switch v := rr.(type) {
					case *dns.A:
						records.A = append(records.A, fmt.Sprintf("%s: %s", v.Hdr.Name, v.A.String()))
					case *dns.AAAA:
						records.AAAA = append(records.AAAA, fmt.Sprintf("%s: %s", v.Hdr.Name, v.AAAA.String()))
					case *dns.CNAME:
						records.CNAME = append(records.CNAME, fmt.Sprintf("%s → %s", v.Hdr.Name, v.Target))
					case *dns.MX:
						records.MX = append(records.MX, fmt.Sprintf("%s (priority: %d)", v.Mx, v.Preference))
					case *dns.TXT:
						records.TXT = append(records.TXT, strings.Join(v.Txt, " "))
					case *dns.NS:
						records.NS = append(records.NS, v.Ns)
					case *dns.CAA:
						records.CAA = append(records.CAA, fmt.Sprintf("%s %d %s", v.Tag, v.Flag, v.Value))
					case *dns.SRV:
						records.SRV = append(records.SRV, fmt.Sprintf("%s:%d (priority: %d, weight: %d)", 
							v.Target, v.Port, v.Priority, v.Weight))
					}
				}
			}
		}
	}

	return records
}

func lookupCAA(domain string) []string {
	var records []string
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeCAA)
	
	c := new(dns.Client)
	if r, _, err := c.Exchange(m, "8.8.8.8:53"); err == nil {
		for _, ans := range r.Answer {
			if caa, ok := ans.(*dns.CAA); ok {
				records = append(records, fmt.Sprintf("%s %d %s", caa.Tag, caa.Flag, caa.Value))
			}
		}
	}
	return records
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

	// Create default resolver for canonical records
	defaultResolver := net.DefaultResolver
	canonicalRecords, err := GetDNSRecords(domain, defaultResolver)
	if err != nil {
		return nil, fmt.Errorf("failed to get canonical records: %w", err)
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

		// Get all DNS records from this nameserver
		nsRecords, err := GetDNSRecords(domain, r)
		if err != nil {
			check.IsConsistent = false
			info.IsConsistent = false
			continue
		}
		check.Records = nsRecords

		// Check consistency by comparing with canonical records
		check.IsConsistent = compareRecords(canonicalRecords, nsRecords)
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

func compareRecords(a, b DNSRecords) bool {
	return compareStringLists(a.A, b.A) &&
		compareStringLists(a.AAAA, b.AAAA) &&
		compareStringLists(a.MX, b.MX) &&
		compareStringLists(a.TXT, b.TXT) &&
		compareStringLists(a.CNAME, b.CNAME) &&
		compareStringLists(a.NS, b.NS) &&
		compareStringLists(a.CAA, b.CAA) &&
		compareStringLists(a.SRV, b.SRV)
}

func compareStringLists(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aMap := make(map[string]bool)
	for _, item := range a {
		aMap[item] = true
	}
	for _, item := range b {
		if !aMap[item] {
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