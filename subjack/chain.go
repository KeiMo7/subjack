package subjack

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

const maxCNAMEDepth = 10

func checkCNAMEChain(domain string, o *Options) {
	checkCNAMEChainCtx(domain, newDomainCtx(o, nil, domain))
}

// checkCNAMEChainCtx follows the full CNAME chain and checks if any
// intermediate or terminal target is an NXDOMAIN with a registrable domain.
func checkCNAMEChainCtx(domain string, dc *domainCtx) {
	var chain []string
	current := domain

	for i := 0; i < maxCNAMEDepth; i++ {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(current), dns.TypeCNAME)
		res := dc.exchange(msg)
		if res.failed() {
			break
		}

		var target string
		for _, a := range res.msg.Answer {
			if t, ok := a.(*dns.CNAME); ok {
				target = t.Target
				break
			}
		}
		if target == "" {
			break
		}

		target = strings.TrimSuffix(target, ".")
		chain = append(chain, target)
		current = target
	}

	// Need at least 2 links to be a chain (beyond what normal detection catches)
	if len(chain) < 2 {
		return
	}

	// Check each link in the chain for takeover opportunities
	for i, link := range chain {
		if i == 0 {
			// Skip first link — already caught by normal CNAME detection
			continue
		}

		nx, res := dc.isNX(link)
		if nx && dc.o.domainAvailable(strings.TrimSuffix(link, ".")) {
			service := "CNAME CHAIN TAKEOVER"
			chainStr := domain + " -> " + strings.Join(chain[:i+1], " -> ")
			detail := fmt.Sprintf("%s - %s is available for registration (chain: %s)", domain, link, chainStr)
			dc.emit(Finding{
				Service: service,
				URL:     domain,
				Detail:  detail,
				Verdict: VerdictVulnerable,
				Ev: &Evidence{
					Resolver: res.resolver,
					Fallback: res.fallback,
					Rcode:    rcodeName(res),
					CNAME:    link,
					Chain:    append([]string{domain}, chain[:i+1]...),
					Reason:   fmt.Sprintf("chain link %s is NXDOMAIN and available for registration", link),
				},
			})
			return
		}
	}
}

func checkSRV(domain string, o *Options) {
	checkSRVCtx(domain, newDomainCtx(o, nil, domain))
}

// checkSRVCtx looks up common SRV records and checks if any targets are
// expired or available for registration.
func checkSRVCtx(domain string, dc *domainCtx) {
	srvPrefixes := []string{
		"_sip._tcp.",
		"_sip._udp.",
		"_sips._tcp.",
		"_xmpp-client._tcp.",
		"_xmpp-server._tcp.",
		"_jabber._tcp.",
		"_h323ls._udp.",
		"_h323cs._tcp.",
		"_imap._tcp.",
		"_imaps._tcp.",
		"_submission._tcp.",
		"_pop3._tcp.",
		"_pop3s._tcp.",
		"_caldav._tcp.",
		"_caldavs._tcp.",
		"_carddav._tcp.",
		"_carddavs._tcp.",
		"_ldap._tcp.",
		"_ldaps._tcp.",
		"_kerberos._tcp.",
		"_kerberos._udp.",
		"_kpasswd._tcp.",
		"_kpasswd._udp.",
		"_minecraft._tcp.",
		"_ts3._udp.",
		"_autodiscover._tcp.",
		"_mta-sts._tcp.",
	}

	for _, prefix := range srvPrefixes {
		qname := prefix + domain
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(qname), dns.TypeSRV)
		res := dc.exchange(msg)
		if res.failed() {
			continue
		}

		for _, a := range res.msg.Answer {
			srv, ok := a.(*dns.SRV)
			if !ok {
				continue
			}
			target := strings.TrimSuffix(srv.Target, ".")
			if target == "" || target == "." {
				continue
			}

			nx, nxres := dc.isNX(target)
			if nx && dc.o.domainAvailable(strings.TrimSuffix(target, ".")) {
				service := "SRV TAKEOVER"
				detail := fmt.Sprintf("%s - SRV %s points to %s which is available for registration", domain, prefix, target)
				dc.emit(Finding{
					Service: service,
					URL:     domain,
					Detail:  detail,
					Verdict: VerdictVulnerable,
					Ev: &Evidence{
						Resolver: nxres.resolver,
						Fallback: nxres.fallback,
						Rcode:    rcodeName(nxres),
						CNAME:    target,
						Reason:   fmt.Sprintf("SRV %s target %s is NXDOMAIN and available for registration", prefix, target),
					},
				})
			}
		}
	}
}
