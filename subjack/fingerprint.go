package subjack

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
)

type Fingerprint struct {
	Service     string   `json:"service"`
	Cname       []string `json:"cname"`
	Fingerprint []string `json:"fingerprint"`
	Nxdomain    bool     `json:"nxdomain"`
}

// matchesCNAME reports whether a CNAME target matches any fingerprint's
// CNAME pattern. Empty patterns are body-only services (e.g. worksites.net)
// and never match by CNAME.
func matchesCNAME(cname string, fingerprints []Fingerprint) bool {
	for _, fp := range fingerprints {
		for _, c := range fp.Cname {
			if c == "" {
				continue
			}
			if strings.Contains(cname, c) {
				return true
			}
		}
	}
	return false
}

func verifyCNAME(subdomain string, o *Options) bool {
	return matchesCNAME(resolveCNAME(subdomain, o), o.fingerprints)
}

func detect(url string, o *Options) {
	detectCtx(url, newDomainCtx(o, nil, url))
}

func detectCtx(url string, dc *domainCtx) {
	services, verdict, ev := identifyCtx(url, dc)
	f := Finding{URL: url, Verdict: verdict, Ev: ev, Services: services}
	if len(services) > 0 {
		f.Service = services[0]
	}
	dc.emitMain(f)
}

// identify preserves the legacy API: the first matching service, or "".
func identify(subdomain string, o *Options) string {
	services, _, _ := identifyCtx(subdomain, newDomainCtx(o, nil, subdomain))
	if len(services) > 0 {
		return services[0]
	}
	return ""
}

// matchBody returns every service whose body fingerprint matches, plus the
// matched patterns, in fingerprint-file order (deterministic).
func matchBody(body []byte, fingerprints []Fingerprint) (services, patterns []string) {
	for _, fp := range fingerprints {
		for _, pattern := range fp.Fingerprint {
			if pattern == "" {
				continue
			}
			if bytes.Contains(body, []byte(pattern)) {
				services = appendUnique(services, strings.ToUpper(fp.Service))
				patterns = appendUnique(patterns, pattern)
				break
			}
		}
	}
	return services, patterns
}

// identifyCtx determines the takeover status of one subdomain and returns
// the matching services, the verdict, and the evidence behind it. DNS
// failures yield VerdictUndetermined — never a silent "not vulnerable".
func identifyCtx(subdomain string, dc *domainCtx) ([]string, Verdict, *Evidence) {
	o := dc.o
	ev := &Evidence{}

	cname, cres := dc.cnameFor(subdomain)
	ev.Resolver = cres.resolver
	ev.Fallback = cres.fallback
	cname = strings.TrimSuffix(cname, ".")
	if len(cname) <= 3 {
		cname = ""
	}
	ev.CNAME = cname

	_, ares := dc.isNX(subdomain)
	if ev.Resolver == "" {
		ev.Resolver = ares.resolver
	}
	if ares.fallback {
		ev.Fallback = true
	}
	ev.Rcode = rcodeName(ares)

	switch ares.status {
	case statusNXDOMAIN:
		if !cres.definitive() {
			ev.Reason = fmt.Sprintf("CNAME lookup inconclusive (%s); cannot evaluate dangling target", cres.status)
			return nil, VerdictUndetermined, ev
		}
		if o.domainAvailable(cname) {
			ev.Reason = "subdomain is NXDOMAIN and its CNAME target is available for registration"
			return []string{"DOMAIN AVAILABLE - " + cname}, VerdictVulnerable, ev
		}

		var services []string
		for _, fp := range o.fingerprints {
			if !fp.Nxdomain {
				continue
			}
			for _, c := range fp.Cname {
				if c == "" || !strings.Contains(cname, c) {
					continue
				}
				service := strings.ToUpper(fp.Service)
				if strings.HasPrefix(service, "AZURE-") {
					service = verifyAzure(service, cname, o)
					if service == "" {
						break
					}
				}
				services = appendUnique(services, service)
				ev.Matched = appendUnique(ev.Matched, c)
				break
			}
		}
		if len(services) > 0 {
			ev.Reason = "subdomain is NXDOMAIN and its CNAME matches a known takeable service"
			return services, VerdictVulnerable, ev
		}

		if o.Manual && cname != "" {
			ev.Reason = "subdomain is NXDOMAIN with a dead CNAME (-m)"
			return []string{"DEAD DOMAIN - " + cname}, VerdictVulnerable, ev
		}

		return nil, VerdictNotVulnerable, ev

	case statusOK:
		// Definitive answer; continue to HTTP probing below.

	default:
		// SERVFAIL, REFUSED, timeout, network or budget errors: the
		// question could not be answered, so no conclusion is drawn.
		ev.Reason = fmt.Sprintf("DNS A lookup inconclusive (%s); cannot determine takeover status", inconclusiveReason(ares))
		return nil, VerdictUndetermined, ev
	}

	hres, err := httpProbeFunc(subdomain, o.Ssl, o.Timeout)
	if err != nil {
		if cname != "" && matchesCNAME(cname, o.fingerprints) {
			ev.Reason = fmt.Sprintf("CNAME %s matches a known service but the HTTP probe failed: %v", cname, err)
			return nil, VerdictUndetermined, ev
		}
		ev.Reason = fmt.Sprintf("HTTP probe failed: %v", err)
		return nil, VerdictNotVulnerable, ev
	}

	ev.HTTPStatus = hres.status
	ev.BodyBytes = len(hres.body)
	ev.BodyTrunc = hres.truncated
	sum := sha1.Sum(hres.body)
	ev.BodySHA1 = hex.EncodeToString(sum[:])[:12]

	services, patterns := matchBody(hres.body, o.fingerprints)
	ev.Matched = patterns
	if len(services) == 0 {
		return nil, VerdictNotVulnerable, ev
	}

	// Wildcard suppression applies only to CNAME-less body matches: a real
	// dangling CNAME is never suppressed by wildcard DNS.
	if cname == "" {
		if wc := dc.wildcardInfoFor(subdomain); wc != nil && wc.wildcard {
			wild := strings.Join(wc.ips, ",")
			probe, perr := httpProbeFunc(wc.probe, o.Ssl, o.Timeout)
			if perr != nil {
				ev.Reason = fmt.Sprintf("wildcard DNS on *.%s (%s) but the probe page was unreachable; not suppressing", wc.parent, wild)
			} else {
				probeServices, _ := matchBody(probe.body, o.fingerprints)
				var remaining, suppressed []string
				for _, s := range services {
					if containsString(probeServices, s) {
						suppressed = append(suppressed, s)
					} else {
						remaining = append(remaining, s)
					}
				}
				if len(remaining) == 0 {
					ev.Reason = fmt.Sprintf("wildcard DNS on *.%s (%s): fingerprint(s) %s also match the unclaimed-probe page",
						wc.parent, wild, strings.Join(services, ", "))
					return nil, VerdictSuppressed, ev
				}
				ev.Reason = fmt.Sprintf("wildcard DNS on *.%s (%s): suppressed fingerprint(s) %s also present on the probe page",
					wc.parent, wild, strings.Join(suppressed, ", "))
				services = remaining
			}
		}
	}

	return services, VerdictVulnerable, ev
}

func containsString(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
