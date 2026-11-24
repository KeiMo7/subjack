package subjack

import (
	"github.com/miekg/dns"
)

// Verdict is the outcome of checking one domain. VerdictUndetermined is
// deliberately distinct from VerdictNotVulnerable: it means the check could
// not be completed (DNS failure, inconclusive probe), not that the domain is
// safe.
type Verdict string

const (
	VerdictVulnerable    Verdict = "vulnerable"
	VerdictNotVulnerable Verdict = "not_vulnerable"
	VerdictUndetermined  Verdict = "undetermined"
	VerdictSuppressed    Verdict = "suppressed"
)

// Evidence carries the proof behind a conclusion: which resolver answered,
// what the DNS rcode was, the CNAME chain, the HTTP status, and which
// fingerprints matched. A conclusion without evidence must not be emitted.
type Evidence struct {
	Resolver   string   `json:"resolver,omitempty"`
	Fallback   bool     `json:"resolver_fallback,omitempty"`
	Rcode      string   `json:"rcode,omitempty"`
	CNAME      string   `json:"cname,omitempty"`
	Chain      []string `json:"chain,omitempty"`
	HTTPStatus int      `json:"http_status,omitempty"`
	BodyBytes  int      `json:"body_bytes,omitempty"`
	BodySHA1   string   `json:"body_sha1,omitempty"`
	BodyTrunc  bool     `json:"body_truncated,omitempty"`
	Matched    []string `json:"matched_fingerprints,omitempty"`
	Reason     string   `json:"reason,omitempty"`
}

// Finding is one conclusion about a domain. Auxiliary findings (NS, SRV,
// AXFR, ...) carry Service+Detail; the main detect finding carries Services
// and is flagged with main=true.
type Finding struct {
	Service  string
	Services []string
	URL      string
	Detail   string
	Verdict  Verdict
	Ev       *Evidence
	main     bool
}

// report aggregates everything learned about one domain so it can be
// rendered atomically, in input order, by the emitter.
type report struct {
	aux  []Finding
	main *Finding
}

// domainCtx carries per-domain state through the checks: the shared Options,
// the report being built (nil renders findings immediately, preserving the
// legacy direct-print behavior), the query budget, and cached lookups for
// the main domain so the gate and identify don't resolve twice.
type domainCtx struct {
	o          *Options
	rep        *report
	budget     *queryBudget
	mainDomain string

	cnameDone bool
	cname     string
	cnameRes  *dnsResult

	aDone bool
	aNX   bool
	aRes  *dnsResult
}

func newDomainCtx(o *Options, rep *report, mainDomain string) *domainCtx {
	return &domainCtx{
		o:          o,
		rep:        rep,
		budget:     &queryBudget{remaining: o.maxQueries()},
		mainDomain: mainDomain,
	}
}

func (dc *domainCtx) exchange(msg *dns.Msg) *dnsResult {
	return exchangeEvidence(msg, dc.o.resolvers, dc.o.timeout(), dc.budget)
}

// cnameFor resolves the CNAME of domain, caching the result for the main
// domain of this context.
func (dc *domainCtx) cnameFor(domain string) (string, *dnsResult) {
	if domain == dc.mainDomain && dc.cnameDone {
		return dc.cname, dc.cnameRes
	}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeCNAME)
	res := dc.exchange(msg)
	var target string
	if res.status == statusOK {
		for _, a := range res.msg.Answer {
			if t, ok := a.(*dns.CNAME); ok {
				target = t.Target
				break
			}
		}
	}
	if domain == dc.mainDomain {
		dc.cnameDone, dc.cname, dc.cnameRes = true, target, res
	}
	return target, res
}

// isNX reports whether domain is NXDOMAIN, classified. The result is cached
// for the main domain.
func (dc *domainCtx) isNX(domain string) (bool, *dnsResult) {
	if domain == dc.mainDomain && dc.aDone {
		return dc.aNX, dc.aRes
	}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	res := dc.exchange(msg)
	nx := res.status == statusNXDOMAIN
	if domain == dc.mainDomain {
		dc.aDone, dc.aNX, dc.aRes = true, nx, res
	}
	return nx, res
}

// emit records an auxiliary finding (NS/SRV/AXFR/... checks).
func (dc *domainCtx) emit(f Finding) {
	if dc.rep == nil {
		renderFinding(f, dc.o)
		return
	}
	dc.rep.aux = append(dc.rep.aux, f)
}

// emitMain records the primary detect verdict for the domain.
func (dc *domainCtx) emitMain(f Finding) {
	f.main = true
	if dc.rep == nil {
		renderFinding(f, dc.o)
		return
	}
	m := f
	dc.rep.main = &m
}

func appendUnique(ss []string, s string) []string {
	for _, x := range ss {
		if x == s {
			return ss
		}
	}
	return append(ss, s)
}
