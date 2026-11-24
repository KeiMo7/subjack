package subjack

import (
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Common nameserver hostname prefixes to bruteforce.
var nsPrefixes = []string{
	"ns", "ns0", "ns1", "ns2", "ns3", "ns4", "ns5",
	"dns", "dns0", "dns1", "dns2", "dns3",
	"dns-0", "dns-1", "dns-2", "dns-3",
	"dns-a", "dns-b", "dns-c", "dns-d",
	"ns-a", "ns-b", "ns-c", "ns-d",
	"ns-0", "ns-1", "ns-2", "ns-3",
	"nsa", "nsb", "nsc", "nsd",
	"dnsa", "dnsb", "dnsc", "dnsd",
	"ns-primary", "ns-secondary",
	"ns-backup", "ns-slave", "ns-master",
	"primary", "secondary",
	"auth-ns0", "auth-ns1", "auth-ns2",
	"cdns1", "cdns2", "cdns3",
	"pdns1", "pdns2",
}

func checkAXFR(domain string, o *Options) {
	checkAXFRCtx(domain, newDomainCtx(o, nil, domain))
}

// checkAXFRCtx attempts zone transfers against a domain's nameservers
// and bruteforced nameserver hostnames.
func checkAXFRCtx(domain string, dc *domainCtx) {
	// Extract the base domain for NS bruteforcing
	baseDomain := getBaseDomain(domain)
	timeout := dc.o.timeout()

	// 1. Try AXFR against actual NS records
	for _, ns := range lookupNSCtx(domain, dc) {
		if tryAXFRCtx(domain, withDNSPort(ns), timeout, dc) {
			return
		}
	}

	// Also try NS records of the base domain if different
	if baseDomain != domain {
		for _, ns := range lookupNSCtx(baseDomain, dc) {
			if tryAXFRCtx(domain, withDNSPort(ns), timeout, dc) {
				return
			}
		}
	}

	// 2. Bruteforce common NS hostnames
	for _, prefix := range nsPrefixes {
		candidate := prefix + "." + baseDomain
		ips, err := net.LookupHost(candidate)
		if err != nil || len(ips) == 0 {
			continue
		}
		if tryAXFRCtx(domain, withDNSPort(candidate), timeout, dc) {
			return
		}
		// Also try AXFR for the base domain on this NS
		if baseDomain != domain {
			if tryAXFRCtx(baseDomain, withDNSPort(candidate), timeout, dc) {
				return
			}
		}
	}
}

func tryAXFR(domain, nsHost string, timeout time.Duration, o *Options) bool {
	return tryAXFRCtx(domain, nsHost, timeout, newDomainCtx(o, nil, domain))
}

func tryAXFRCtx(domain, nsHost string, timeout time.Duration, dc *domainCtx) bool {
	transfer := &dns.Transfer{
		DialTimeout:  timeout,
		ReadTimeout:  timeout,
		WriteTimeout: timeout,
	}

	msg := new(dns.Msg)
	msg.SetAxfr(dns.Fqdn(domain))

	ch, err := transfer.In(msg, nsHost)
	if err != nil {
		return false
	}

	var records []string
	for envelope := range ch {
		// A clean end-of-stream is delivered as a final envelope carrying
		// io.EOF once the server closes the connection; that is success,
		// not an error.
		if envelope.Error == io.EOF {
			break
		}
		if envelope.Error != nil {
			return false
		}
		for _, rr := range envelope.RR {
			records = append(records, rr.String())
		}
	}

	if len(records) == 0 {
		return false
	}

	service := "ZONE TRANSFER"
	detail := fmt.Sprintf("%s - AXFR successful on %s (%d records)", domain, nsHost, len(records))

	dc.emit(Finding{
		Service: service,
		URL:     domain,
		Detail:  detail,
		Verdict: VerdictVulnerable,
		Ev: &Evidence{
			Reason: fmt.Sprintf("nameserver %s allowed a zone transfer of %d records", nsHost, len(records)),
		},
	})
	return true
}

func getBaseDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		return domain
	}
	return strings.Join(parts[len(parts)-2:], ".")
}
