package subjack

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// wildcardHandler answers A queries for any name under zone with ip (a
// wildcard), delegating everything else to the fakeDNS fixture.
func wildcardHandler(zone, ip string, fx *fakeDNS) dns.HandlerFunc {
	inner := fx.handler()
	suffix := strings.TrimSuffix(zone, ".") + "."
	return func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		name := strings.ToLower(q.Name)
		if q.Qtype == dns.TypeA && strings.HasSuffix(name, suffix) && !fx.nxdomain[name] {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Answer = append(m.Answer, &dns.A{Hdr: rrHdr(name, dns.TypeA), A: net.ParseIP(ip)})
			w.WriteMsg(m)
			return
		}
		inner(w, r)
	}
}

// stubHTTP routes HTTP probes to fixture bodies keyed by host, so wildcard
// tests do not depend on system DNS. The wildcard probe name is matched by
// prefix.
func stubHTTP(t *testing.T, bodies map[string]string) {
	t.Helper()
	overrideVar(t, &httpProbeFunc, func(url string, ssl bool, timeout int) (*httpResponse, error) {
		for host, body := range bodies {
			if strings.HasPrefix(url, host) {
				return &httpResponse{body: []byte(body), status: 200}, nil
			}
		}
		return nil, errors.New("no such host")
	})
}

const githubBody = "There isn't a GitHub Pages site here."

func TestWildcardSuppressesProbeMatchedFingerprint(t *testing.T) {
	fx := &fakeDNS{}
	addr := startTestDNSServer(t, wildcardHandler(".wc.test", "10.0.0.1", fx))
	o := newTestOptions(t, addr)

	// The unclaimed-probe page shows the same fingerprint as the domain:
	// the match is a wildcard artifact and must be suppressed, with an
	// explanation.
	stubHTTP(t, map[string]string{
		"www.wc.test": githubBody,
		"subjack-wc-": githubBody,
	})

	services, verdict, ev := identifyCtx("www.wc.test", newDomainCtx(o, nil, "www.wc.test"))
	if verdict != VerdictSuppressed {
		t.Fatalf("verdict = %q, want %q", verdict, VerdictSuppressed)
	}
	if len(services) != 0 {
		t.Errorf("services = %v, want none (suppressed)", services)
	}
	if ev == nil {
		t.Fatal("no evidence attached")
	} else if !strings.Contains(ev.Reason, "wildcard") {
		t.Errorf("reason = %q, want an explanation naming the wildcard", ev.Reason)
	}
	if !strings.Contains(ev.Reason, "10.0.0.1") {
		t.Errorf("reason = %q, want it to include the wildcard IPs", ev.Reason)
	}
}

func TestWildcardDoesNotSuppressRealFingerprint(t *testing.T) {
	fx := &fakeDNS{}
	addr := startTestDNSServer(t, wildcardHandler(".wc.test", "10.0.0.1", fx))
	o := newTestOptions(t, addr)

	// The probe page does NOT show the fingerprint: the match on the domain
	// is real and must survive wildcard suppression.
	stubHTTP(t, map[string]string{
		"www.wc.test": githubBody,
		"subjack-wc-": "just a parked page",
	})

	services, verdict, ev := identifyCtx("www.wc.test", newDomainCtx(o, nil, "www.wc.test"))
	if verdict != VerdictVulnerable {
		t.Fatalf("verdict = %q, want %q (real takeover must not be suppressed)", verdict, VerdictVulnerable)
	}
	if len(services) != 1 || services[0] != "GITHUB" {
		t.Errorf("services = %v, want [GITHUB]", services)
	}
	if ev == nil {
		t.Fatal("no evidence attached")
	} else if !strings.Contains(ev.Reason, "wildcard") {
		t.Errorf("reason = %q, want it to note the wildcard context", ev.Reason)
	}
}

func TestWildcardNeverSuppressesDanglingCNAME(t *testing.T) {
	fx := &fakeDNS{
		cname:    map[string]string{"www2.wc.test.": "gone.buyable.test"},
		nxdomain: map[string]bool{"www2.wc.test.": true},
	}
	addr := startTestDNSServer(t, wildcardHandler(".wc.test", "10.0.0.1", fx))
	o := newTestOptions(t, addr)
	setAvailable(o, "gone.buyable.test")
	stubHTTP(t, map[string]string{"subjack-wc-": githubBody})

	services, verdict, _ := identifyCtx("www2.wc.test", newDomainCtx(o, nil, "www2.wc.test"))
	if verdict != VerdictVulnerable {
		t.Fatalf("verdict = %q, want %q (dangling CNAME under a wildcard zone)", verdict, VerdictVulnerable)
	}
	if len(services) != 1 || services[0] != "DOMAIN AVAILABLE - gone.buyable.test" {
		t.Errorf("services = %v, want DOMAIN AVAILABLE", services)
	}
}

func TestParentDomain(t *testing.T) {
	cases := map[string]string{
		"www.app.test":      "app.test",
		"deep.sub.app.test": "sub.app.test",
		"app.test":          "",
		"127.0.0.1":         "",
		"127.0.0.1:8080":    "",
	}
	for in, want := range cases {
		if got := parentDomain(in); got != want {
			t.Errorf("parentDomain(%q) = %q, want %q", in, got, want)
		}
	}
}
