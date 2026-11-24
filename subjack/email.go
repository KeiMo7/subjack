package subjack

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

func checkSPF(domain string, o *Options) {
	checkSPFCtx(domain, newDomainCtx(o, nil, domain))
}

// checkSPFCtx parses SPF TXT records for include: domains and checks if any
// are expired or available for registration.
func checkSPFCtx(domain string, dc *domainCtx) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeTXT)
	res := dc.exchange(msg)
	if res.failed() {
		return
	}

	for _, a := range res.msg.Answer {
		txt, ok := a.(*dns.TXT)
		if !ok {
			continue
		}
		record := strings.Join(txt.Txt, "")
		if !strings.HasPrefix(record, "v=spf1") {
			continue
		}

		for _, part := range strings.Fields(record) {
			if !strings.HasPrefix(part, "include:") {
				continue
			}
			includeDomain := strings.TrimPrefix(part, "include:")
			if includeDomain == "" {
				continue
			}

			nx, nxres := dc.isNX(includeDomain)
			if nx && dc.o.domainAvailable(includeDomain) {
				service := "SPF TAKEOVER"
				detail := fmt.Sprintf("%s - SPF include:%s is available for registration", domain, includeDomain)
				dc.emit(Finding{
					Service: service,
					URL:     domain,
					Detail:  detail,
					Verdict: VerdictVulnerable,
					Ev: &Evidence{
						Resolver: nxres.resolver,
						Fallback: nxres.fallback,
						Rcode:    rcodeName(nxres),
						CNAME:    includeDomain,
						Reason:   fmt.Sprintf("SPF include:%s is NXDOMAIN and available for registration", includeDomain),
					},
				})
			}
		}
	}
}

func checkMX(domain string, o *Options) {
	checkMXCtx(domain, newDomainCtx(o, nil, domain))
}

// checkMXCtx checks if any MX record targets are expired or available for
// registration.
func checkMXCtx(domain string, dc *domainCtx) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeMX)
	res := dc.exchange(msg)
	if res.failed() {
		return
	}

	for _, a := range res.msg.Answer {
		mx, ok := a.(*dns.MX)
		if !ok {
			continue
		}
		mxHost := strings.TrimSuffix(mx.Mx, ".")
		if mxHost == "" {
			continue
		}

		nx, nxres := dc.isNX(mxHost)
		if nx && dc.o.domainAvailable(mxHost) {
			service := "MX TAKEOVER"
			detail := fmt.Sprintf("%s - mail server %s is available for registration", domain, mxHost)
			dc.emit(Finding{
				Service: service,
				URL:     domain,
				Detail:  detail,
				Verdict: VerdictVulnerable,
				Ev: &Evidence{
					Resolver: nxres.resolver,
					Fallback: nxres.fallback,
					Rcode:    rcodeName(nxres),
					CNAME:    mxHost,
					Reason:   fmt.Sprintf("MX target %s is NXDOMAIN and available for registration", mxHost),
				},
			})
		}
	}
}
