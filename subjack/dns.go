package subjack

import (
	"errors"
	"fmt"
	"hash/fnv"
	"math/rand/v2"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// defaultResolver is used when no resolver list is given, and as the
// fallback when a custom resolver fails. It is a variable so tests can
// point it at a local fixture.
var defaultResolver = "8.8.8.8:53"

// Resolution statuses. Every DNS answer the scanner acts on is classified
// into exactly one of these so "the network didn't cooperate" can never be
// mistaken for "no problem found".
const (
	statusOK       = "ok"
	statusNXDOMAIN = "nxdomain"
	statusSERVFAIL = "servfail"
	statusREFUSED  = "refused"
	statusTimeout  = "timeout"
	statusError    = "error"
)

// retryBackoff is the delay between bounded retry attempts.
const retryBackoff = 100 * time.Millisecond

// errQueryBudgetExhausted is returned when a domain has used up its
// per-domain DNS query allowance.
var errQueryBudgetExhausted = errors.New("per-domain query budget exhausted")

// queryBudget bounds how many DNS exchanges a single domain may cause,
// including retries. It makes per-domain query growth provably bounded.
type queryBudget struct{ remaining int }

func (b *queryBudget) take() bool {
	if b == nil {
		return true
	}
	if b.remaining <= 0 {
		return false
	}
	b.remaining--
	return true
}

// dnsResult is a classified DNS exchange with the evidence of how the
// answer (or failure) was obtained.
type dnsResult struct {
	msg      *dns.Msg
	status   string // one of the status* constants
	resolver string // resolver that produced this result
	fallback bool   // true when we switched away from the chosen resolver
	attempts int    // network exchanges performed
	err      error
}

func (r *dnsResult) failed() bool { return r.err != nil }

// definitive reports whether the result is a conclusive answer (NOERROR or
// NXDOMAIN) rather than a failure or an inconclusive rcode.
func (r *dnsResult) definitive() bool {
	return r.status == statusOK || r.status == statusNXDOMAIN
}

// normalizeResolver turns a bare IP, bare hostname, or host:port into a
// host:port resolver address.
func normalizeResolver(r string) string {
	if net.ParseIP(r) != nil {
		return net.JoinHostPort(r, "53")
	}
	if _, _, err := net.SplitHostPort(r); err == nil {
		return r
	}
	return net.JoinHostPort(r, "53")
}

// pickResolver picks a random resolver from the list. Entries may be bare
// IPs or hostnames (port 53 is appended) or full host:port addresses.
func pickResolver(resolvers []string) string {
	if len(resolvers) == 0 {
		return defaultResolver
	}
	return normalizeResolver(resolvers[rand.IntN(len(resolvers))])
}

// pickResolverFor picks a resolver deterministically from the list, keyed on
// the query, so identical inputs produce identical resolver choices (and
// identical evidence) across runs.
func pickResolverFor(resolvers []string, key string) string {
	if len(resolvers) == 0 {
		return defaultResolver
	}
	h := fnv.New32a()
	h.Write([]byte(key))
	return normalizeResolver(resolvers[int(h.Sum32())%len(resolvers)])
}

// validResolverEntry reports whether a resolver-list entry is usable: a bare
// IP, a host:port with a numeric port, or a plausible hostname.
func validResolverEntry(e string) bool {
	if net.ParseIP(e) != nil {
		return true
	}
	if _, port, err := net.SplitHostPort(e); err == nil {
		p, err := strconv.Atoi(port)
		return err == nil && p > 0 && p <= 65535
	}
	return validHostname(e)
}

func validHostname(h string) bool {
	if len(h) == 0 || len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(h, "."), ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for i, c := range label {
			ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') || c == '-' || c == '_'
			if !ok {
				return false
			}
			if c == '-' && (i == 0 || i == len(label)-1) {
				return false
			}
		}
	}
	return true
}

// validateResolvers splits a resolver list into usable and invalid entries.
// Blank lines are skipped silently; malformed entries are reported so the
// caller can surface them instead of silently working around them.
func validateResolvers(entries []string) (valid, invalid []string) {
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if validResolverEntry(e) {
			valid = append(valid, e)
		} else {
			invalid = append(invalid, e)
		}
	}
	return valid, invalid
}

// exchangeEvidence performs one logical DNS query with bounded retries and
// backoff, and records exactly what happened. A failing custom resolver
// falls back to the default resolver at most once, and that switch is always
// recorded in the result (never silent). The budget, when non-nil, caps the
// number of network exchanges.
func exchangeEvidence(msg *dns.Msg, resolvers []string, timeout time.Duration, budget *queryBudget) *dnsResult {
	res := &dnsResult{}
	key := ""
	if len(msg.Question) > 0 {
		q := msg.Question[0]
		key = q.Name + "/" + strconv.Itoa(int(q.Qtype))
	}
	resolver := pickResolverFor(resolvers, key)
	res.resolver = resolver
	client := &dns.Client{Timeout: timeout}

	try := func(addr string) (*dns.Msg, error) {
		if !budget.take() {
			return nil, errQueryBudgetExhausted
		}
		res.attempts++
		resp, _, err := client.Exchange(msg, addr)
		return resp, err
	}

	resp, err := try(resolver)
	if err != nil && !errors.Is(err, errQueryBudgetExhausted) {
		// One bounded retry of the chosen resolver, with backoff.
		time.Sleep(retryBackoff)
		resp, err = try(resolver)
	}
	if err != nil && resolver != defaultResolver && !errors.Is(err, errQueryBudgetExhausted) {
		// Explicit, recorded fallback to the default resolver.
		chosenErr := err
		time.Sleep(retryBackoff)
		resp, err = try(defaultResolver)
		// The switch is recorded whether or not the fallback answered.
		res.fallback = true
		res.resolver = defaultResolver
		if err != nil {
			// The fallback failed too: classify by the chosen resolver's
			// failure, which is the more informative of the two.
			err = chosenErr
		}
	}

	if err != nil {
		res.err = err
		var ne net.Error
		switch {
		case errors.Is(err, errQueryBudgetExhausted):
			res.status = statusError
		case errors.As(err, &ne) && ne.Timeout():
			res.status = statusTimeout
		default:
			res.status = statusError
		}
		return res
	}

	res.msg = resp
	switch resp.Rcode {
	case dns.RcodeNameError:
		res.status = statusNXDOMAIN
	case dns.RcodeServerFailure:
		res.status = statusSERVFAIL
	case dns.RcodeRefused:
		res.status = statusREFUSED
	default:
		res.status = statusOK
	}
	return res
}

// dnsExchange preserves the legacy API: one exchange with fallback to the
// default resolver. It is a thin wrapper over exchangeEvidence.
func dnsExchange(msg *dns.Msg, resolvers []string, timeout time.Duration) (*dns.Msg, error) {
	r := exchangeEvidence(msg, resolvers, timeout, nil)
	return r.msg, r.err
}

// rcodeName renders the result rcode/status as evidence text.
func rcodeName(res *dnsResult) string {
	if res == nil {
		return ""
	}
	if res.msg != nil {
		if s, ok := dns.RcodeToString[res.msg.Rcode]; ok {
			return s
		}
	}
	return strings.ToUpper(res.status)
}

// inconclusiveReason describes why a DNS result cannot support a
// conclusion, distinguishing budget exhaustion from network failures.
func inconclusiveReason(res *dnsResult) string {
	if errors.Is(res.err, errQueryBudgetExhausted) {
		return "per-domain query budget exhausted"
	}
	return res.status
}

func (o *Options) timeout() time.Duration {
	return time.Duration(o.Timeout) * time.Second
}

// maxQueries returns the per-domain DNS query budget.
func (o *Options) maxQueries() int {
	if o.MaxQueries > 0 {
		return o.MaxQueries
	}
	return defaultMaxDomainQueries
}

const defaultMaxDomainQueries = 200

// runDomain executes every enabled check for one domain. When dc.rep is nil
// findings render immediately (legacy behavior); otherwise they accumulate
// into the report for ordered emission.
func runDomain(url string, dc *domainCtx) *report {
	o := dc.o
	if o.sem != nil {
		o.sem <- struct{}{}
		defer func() { <-o.sem }()
	}

	if o.CheckNS {
		checkNSCtx(url, dc)
		checkDanglingNSCtx(url, dc)
	}

	if o.CheckAR {
		checkARecordCtx(url, dc)
	}

	if o.CheckAXFR {
		checkAXFRCtx(url, dc)
	}

	if o.CheckMail {
		checkSPFCtx(url, dc)
		checkMXCtx(url, dc)
	}

	if o.CheckSRV {
		checkSRVCtx(url, dc)
	}

	checkCNAMEChainCtx(url, dc)

	if o.All {
		detectCtx(url, dc)
		return dc.rep
	}

	cname, cres := dc.cnameFor(url)
	if !cres.definitive() {
		// The gate itself could not be evaluated. Only conclude
		// "undetermined" when the A lookup is inconclusive too; a
		// definitive A answer still lets the gate run.
		if _, ares := dc.isNX(url); !ares.definitive() {
			ev := &Evidence{
				Resolver: cres.resolver,
				Fallback: cres.fallback,
				Rcode:    rcodeName(cres),
				Reason:   fmt.Sprintf("DNS resolution inconclusive (%s); cannot determine takeover status", inconclusiveReason(cres)),
			}
			dc.emitMain(Finding{URL: url, Verdict: VerdictUndetermined, Ev: ev})
			return dc.rep
		}
	}

	if matchesCNAME(cname, o.fingerprints) {
		detectCtx(url, dc)
		return dc.rep
	}

	if o.Verbose {
		dc.emitMain(Finding{URL: url, Verdict: VerdictNotVulnerable})
	}
	return dc.rep
}

// check preserves the legacy single-domain entry point used by tests and
// prints findings immediately.
func check(url string, o *Options) {
	runDomain(url, newDomainCtx(o, nil, url))
}

func resolveCNAME(domain string, o *Options) string {
	target, _ := newDomainCtx(o, nil, domain).cnameFor(domain)
	return target
}

func lookupNS(domain string, o *Options) []string {
	return lookupNSCtx(domain, newDomainCtx(o, nil, domain))
}

func lookupNSCtx(domain string, dc *domainCtx) []string {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	res := dc.exchange(msg)
	if res.failed() {
		return nil
	}

	var nameservers []string
	for _, a := range res.msg.Answer {
		if t, ok := a.(*dns.NS); ok {
			nameservers = append(nameservers, t.Ns)
		}
	}
	return nameservers
}

func isNXDOMAIN(host string, o *Options) bool {
	nx, _ := newDomainCtx(o, nil, host).isNX(host)
	return nx
}

func checkNS(domain string, o *Options) {
	checkNSCtx(domain, newDomainCtx(o, nil, domain))
}

func checkNSCtx(domain string, dc *domainCtx) {
	for _, ns := range lookupNSCtx(domain, dc) {
		nx, res := dc.isNX(ns)
		if nx && dc.o.domainAvailable(normalizeDomain(ns)) {
			service := "NS TAKEOVER"
			nsName := strings.TrimSuffix(ns, ".")
			detail := fmt.Sprintf("%s - nameserver %s is available for purchase!", domain, nsName)
			dc.emit(Finding{
				Service: service,
				URL:     domain,
				Detail:  detail,
				Verdict: VerdictVulnerable,
				Ev: &Evidence{
					Resolver: res.resolver,
					Fallback: res.fallback,
					Rcode:    rcodeName(res),
					Reason:   fmt.Sprintf("nameserver %s is NXDOMAIN and available for registration", nsName),
				},
			})
		}
	}
}
