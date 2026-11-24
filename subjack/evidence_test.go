package subjack

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// rcodeServer returns a DNS handler that answers every query with the given
// rcode.
func rcodeHandler(rcode int) dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, rcode)
		w.WriteMsg(m)
	}
}

func TestExchangeClassification(t *testing.T) {
	cases := []struct {
		name    string
		handler dns.HandlerFunc
		want    string
	}{
		{"ok", (&fakeDNS{a: map[string][]string{"x.test.": {"127.0.0.1"}}}).handler(), statusOK},
		{"nxdomain", rcodeHandler(dns.RcodeNameError), statusNXDOMAIN},
		{"servfail", rcodeHandler(dns.RcodeServerFailure), statusSERVFAIL},
		{"refused", rcodeHandler(dns.RcodeRefused), statusREFUSED},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr := startTestDNSServer(t, tc.handler)
			msg := new(dns.Msg)
			msg.SetQuestion("x.test.", dns.TypeA)
			res := exchangeEvidence(msg, []string{addr}, time.Second, nil)
			if res.status != tc.want {
				t.Errorf("status = %q, want %q (err=%v)", res.status, tc.want, res.err)
			}
			if res.resolver != addr {
				t.Errorf("resolver = %q, want %q", res.resolver, addr)
			}
			if res.fallback {
				t.Error("fallback = true, want false for a healthy resolver")
			}
		})
	}
}

func TestExchangeTimeoutClassified(t *testing.T) {
	// A handler that never writes a response: the client must time out.
	blackhole := startTestDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {}))
	// The fallback target refuses fast so the test does not hit the network.
	overrideVar(t, &defaultResolver, "127.0.0.1:1")

	msg := new(dns.Msg)
	msg.SetQuestion("slow.test.", dns.TypeA)
	res := exchangeEvidence(msg, []string{blackhole}, time.Second, nil)

	if res.status != statusTimeout {
		t.Errorf("status = %q, want %q (err=%v)", res.status, statusTimeout, res.err)
	}
	if res.err == nil {
		t.Error("err = nil, want a timeout error")
	}
	// Two attempts on the chosen resolver plus one fallback attempt:
	// retries are bounded, not unbounded.
	if res.attempts > 3 {
		t.Errorf("attempts = %d, want <= 3 (bounded retries)", res.attempts)
	}
	if !res.fallback {
		t.Error("fallback = false, want true: the switch to the default resolver must be recorded")
	}
}

func TestExchangeFallbackRecorded(t *testing.T) {
	addr := startTestDNSServer(t, (&fakeDNS{
		a: map[string][]string{"fallback.test.": {"127.0.0.1"}},
	}).handler())
	overrideVar(t, &defaultResolver, addr)

	msg := new(dns.Msg)
	msg.SetQuestion("fallback.test.", dns.TypeA)
	res := exchangeEvidence(msg, []string{"127.0.0.1:1"}, 2*time.Second, nil)

	if res.err != nil || res.status != statusOK {
		t.Fatalf("fallback exchange failed: status=%q err=%v", res.status, res.err)
	}
	if !res.fallback {
		t.Error("fallback = false, want true")
	}
	if res.resolver != addr {
		t.Errorf("resolver = %q, want the default resolver %q", res.resolver, addr)
	}
}

func TestValidateResolvers(t *testing.T) {
	entries := []string{
		"1.1.1.1",
		"127.0.0.1:5353",
		"[::1]:5353",
		"2001:4860:4860::8888",
		"dns.example.com",
		"",
		"   ",
		"not a resolver!!",
		"http://1.2.3.4",
		"1.2.3.4:notaport",
		"1.2.3.4:99999",
	}
	valid, invalid := validateResolvers(entries)
	if len(valid) != 5 {
		t.Errorf("valid = %v, want 5 entries", valid)
	}
	if len(invalid) != 4 {
		t.Errorf("invalid = %v, want 4 entries", invalid)
	}
	for _, bad := range invalid {
		if strings.TrimSpace(bad) == "" {
			t.Errorf("blank entry %q reported as invalid; blanks should be skipped silently", bad)
		}
	}
}

func TestQueryBudgetCapsExchanges(t *testing.T) {
	var queries atomic.Int32
	fx := &fakeDNS{}
	fx.onQuery = func(q dns.Question) { queries.Add(1) }
	addr := startTestDNSServer(t, fx.handler())

	o := newTestOptions(t, addr)
	o.MaxQueries = 5
	o.CheckSRV = true // would normally send 28 SRV queries

	check("capped.test", o)

	if n := queries.Load(); n > 5 {
		t.Errorf("server saw %d queries, want <= 5 (budget must cap per-domain queries)", n)
	}
}

func TestQueryBudgetExhaustedIsUndetermined(t *testing.T) {
	addr := startTestDNSServer(t, (&fakeDNS{
		cname: map[string]string{"app.test.": "gone.buyable.test"},
	}).handler())
	o := newTestOptions(t, addr)
	o.MaxQueries = 1 // the CNAME lookup consumes the whole budget

	_, verdict, ev := identifyCtx("app.test", newDomainCtx(o, nil, "app.test"))
	if verdict != VerdictUndetermined {
		t.Errorf("verdict = %q, want %q when the budget runs out", verdict, VerdictUndetermined)
	}
	if ev == nil {
		t.Fatal("no evidence attached")
	} else if !strings.Contains(ev.Reason, "budget") {
		t.Errorf("reason = %q, want it to name the query budget", ev.Reason)
	}
}

func TestDeterministicResolverPick(t *testing.T) {
	resolvers := []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}
	first := pickResolverFor(resolvers, "app.test./1")
	for i := 0; i < 10; i++ {
		if got := pickResolverFor(resolvers, "app.test./1"); got != first {
			t.Fatalf("pickResolverFor not deterministic: %q then %q", first, got)
		}
	}
}
