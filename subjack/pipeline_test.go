package subjack

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// pipelineFixture builds a DNS handler covering every verdict category:
// dangling CNAME, SERVFAIL, multi-fingerprint, clean, wildcard-suppressed,
// and wildcard-with-real-fingerprint.
func pipelineFixture() dns.HandlerFunc {
	fx := &fakeDNS{
		cname:    map[string]string{"vuln.app.test.": "gone.buyable.test"},
		nxdomain: map[string]bool{"vuln.app.test.": true},
	}
	inner := fx.handler()
	return func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		name := strings.ToLower(q.Name)
		switch {
		case name == "svcfail.app.test." && q.Qtype == dns.TypeA:
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeServerFailure)
			w.WriteMsg(m)
		case q.Qtype == dns.TypeA && strings.HasSuffix(name, ".wildzone.test."):
			m := new(dns.Msg)
			m.SetReply(r)
			m.Answer = append(m.Answer, &dns.A{Hdr: rrHdr(name, dns.TypeA), A: net.ParseIP("10.9.9.9")})
			w.WriteMsg(m)
		default:
			inner(w, r)
		}
	}
}

// pipelineHTTP serves deterministic bodies for the fixture domains.
func pipelineHTTP(t *testing.T) {
	t.Helper()
	stubHTTP(t, map[string]string{
		"multi.site.test":    githubBody + " The specified bucket does not exist",
		"plain.site.test":    "just a normal page",
		"wild.wildzone.test": githubBody,
		"real.wildzone.test": "The specified bucket does not exist",
		"subjack-wc-":        githubBody,
	})
}

var pipelineDomains = []string{
	"vuln.app.test",
	"svcfail.app.test",
	"multi.site.test",
	"plain.site.test",
	"wild.wildzone.test",
	"real.wildzone.test",
}

func runPipeline(t *testing.T, addr string, threads int) (stdout, jsonOut string) {
	t.Helper()

	wordlist := filepath.Join(t.TempDir(), "subs.txt")
	if err := os.WriteFile(wordlist, []byte(strings.Join(pipelineDomains, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	o := newTestOptions(t, addr)
	o.Threads = threads
	o.Wordlist = wordlist
	o.All = true
	o.Output = filepath.Join(t.TempDir(), "results.json")
	setAvailable(o, "gone.buyable.test")

	stdout = captureStdout(t, func() { Process(o) })
	data, err := os.ReadFile(o.Output)
	if err != nil {
		t.Fatalf("reading json output: %v", err)
	}
	return stdout, string(data)
}

func TestProcessDeterministic(t *testing.T) {
	addr := startTestDNSServer(t, pipelineFixture())
	pipelineHTTP(t)

	baseOut, baseJSON := runPipeline(t, addr, 8)
	for i := 0; i < 2; i++ {
		out, js := runPipeline(t, addr, 8)
		if out != baseOut {
			t.Fatalf("run %d stdout differs:\n--- run 0 ---\n%s\n--- run %d ---\n%s", i+1, baseOut, i+1, out)
		}
		if js != baseJSON {
			t.Fatalf("run %d JSON differs:\n--- run 0 ---\n%s\n--- run %d ---\n%s", i+1, baseJSON, i+1, js)
		}
	}
	// Concurrency level must not change conclusions or order.
	out1, js1 := runPipeline(t, addr, 1)
	if out1 != baseOut || js1 != baseJSON {
		t.Fatalf("threads=1 output differs from threads=8:\n%s\n%s", out1, js1)
	}

	// Spot-check the content itself.
	for _, want := range []string{
		"[DOMAIN AVAILABLE - gone.buyable.test] vuln.app.test",
		"[Undetermined] svcfail.app.test",
		"[GITHUB] multi.site.test",
		"[S3 BUCKET] multi.site.test",
		"[Not Vulnerable] plain.site.test",
		"[Suppressed] wild.wildzone.test",
		"[S3 BUCKET] real.wildzone.test",
	} {
		if !strings.Contains(baseOut, want) {
			t.Errorf("stdout missing %q:\n%s", want, baseOut)
		}
	}
	if strings.Contains(baseOut, githubBody) {
		t.Error("stdout contains a raw response body; bodies must never be emitted")
	}
}

func TestProcessUndeterminedCounted(t *testing.T) {
	addr := startTestDNSServer(t, pipelineFixture())
	pipelineHTTP(t)

	wordlist := filepath.Join(t.TempDir(), "subs.txt")
	os.WriteFile(wordlist, []byte("svcfail.app.test\nplain.site.test\n"), 0600)

	o := newTestOptions(t, addr)
	o.Wordlist = wordlist
	o.All = true
	o.Output = filepath.Join(t.TempDir(), "results.json")

	stderr := captureStderr(t, func() { Process(o) })

	if !strings.Contains(stderr, "undetermined=1") {
		t.Errorf("summary = %q, want undetermined=1", stderr)
	}
	if !strings.Contains(stderr, "not_vulnerable=1") {
		t.Errorf("summary = %q, want not_vulnerable=1", stderr)
	}

	results := readOutputJSON(t, o.Output)
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2: %+v", len(results), results)
	}
	var und *Result
	for i := range results {
		if results[i].Subdomain == "svcfail.app.test" {
			und = &results[i]
		}
	}
	if und == nil {
		t.Fatalf("no JSON entry for svcfail.app.test: %+v", results)
	}
	if und.Vulnerable {
		t.Error("undetermined entry must not be marked vulnerable")
	}
	if und.Verdict != "undetermined" {
		t.Errorf("verdict = %q, want undetermined", und.Verdict)
	}
	if und.Evidence == nil || und.Evidence.Rcode != "SERVFAIL" {
		t.Errorf("evidence = %+v, want rcode SERVFAIL", und.Evidence)
	}
	if und.Evidence.Resolver == "" {
		t.Error("evidence must name the resolver used")
	}
}

func TestProcessStreamingStdinMemoryBounded(t *testing.T) {
	addr := startTestDNSServer(t, (&fakeDNS{}).handler())

	const n = 50000
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for i := 0; i < n; i++ {
			fmt.Fprintf(w, "d%d.stream.test\n", i)
		}
		w.Close()
	}()

	oldStdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = oldStdin })

	o := newTestOptions(t, addr)
	o.Threads = 32
	o.Stdin = true
	o.Output = "" // no output file; stdout is not verbose so stays quiet
	o.Verbose = false

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	stderr := captureStderr(t, func() { Process(o) })

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	if !strings.Contains(stderr, "total=50000") {
		t.Errorf("summary = %q, want total=50000", stderr)
	}

	delta := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	const bound = 128 << 20 // 128 MiB
	if delta > bound {
		t.Errorf("heap grew by %d bytes processing %d streaming domains, want <= %d (input must not be buffered wholesale)", delta, n, bound)
	}
}

func TestProcessInvalidResolversReported(t *testing.T) {
	addr := startTestDNSServer(t, e2eFixture().handler())

	resolvers := filepath.Join(t.TempDir(), "resolvers.txt")
	content := "not a resolver!!\nhttp://bad.example\n" + addr + "\n"
	if err := os.WriteFile(resolvers, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	o := newTestOptions(t, "127.0.0.1:1")
	o.ResolverList = resolvers
	o.Domain = "vuln.app.test"
	o.All = true
	o.Output = filepath.Join(t.TempDir(), "results.json")
	setAvailable(o, "gone.buyable.test")

	stderr := captureStderr(t, func() { Process(o) })

	if !strings.Contains(stderr, `ignoring invalid resolver entry "not a resolver!!"`) {
		t.Errorf("stderr = %q, want the invalid entry reported", stderr)
	}
	if !strings.Contains(stderr, `ignoring invalid resolver entry "http://bad.example"`) {
		t.Errorf("stderr = %q, want the invalid entry reported", stderr)
	}

	results := readOutputJSON(t, o.Output)
	if len(results) != 1 || !results[0].Vulnerable {
		t.Fatalf("results = %+v, want detection via the valid resolver", results)
	}
	if results[0].Evidence == nil || !strings.HasPrefix(results[0].Evidence.Resolver, "127.0.0.1:") {
		t.Errorf("evidence resolver = %+v, want the fixture resolver recorded", results[0].Evidence)
	}
}

func TestProcessAllInvalidResolversFallsBackLoudly(t *testing.T) {
	addr := startTestDNSServer(t, e2eFixture().handler())
	overrideVar(t, &defaultResolver, addr)

	resolvers := filepath.Join(t.TempDir(), "resolvers.txt")
	os.WriteFile(resolvers, []byte("garbage!!\n"), 0600)

	o := newTestOptions(t, "127.0.0.1:1")
	o.ResolverList = resolvers
	o.Domain = "vuln.app.test"
	o.All = true
	o.Output = filepath.Join(t.TempDir(), "results.json")
	setAvailable(o, "gone.buyable.test")

	stderr := captureStderr(t, func() { Process(o) })
	if !strings.Contains(stderr, "no usable resolvers") {
		t.Errorf("stderr = %q, want an explicit notice that the default resolver is in use", stderr)
	}
}

func TestProcessOutputWriteFailurePreservesConclusions(t *testing.T) {
	addr := startTestDNSServer(t, e2eFixture().handler())

	o := newTestOptions(t, addr)
	o.Domain = "vuln.app.test"
	o.All = true
	o.Output = filepath.Join(t.TempDir(), "missing-dir", "out.txt") // cannot be created
	setAvailable(o, "gone.buyable.test")

	var code int
	stdout := captureStdout(t, func() { code = Process(o) })

	if code != 1 {
		t.Errorf("exit code = %d, want 1 on output failure", code)
	}
	if !strings.Contains(stdout, "DOMAIN AVAILABLE") {
		t.Errorf("stdout = %q, conclusions must be preserved even when the output file fails", stdout)
	}
}

func TestHTTPStatusAndBodyHashInEvidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(githubBody))
	}))
	t.Cleanup(srv.Close)

	addr := startTestDNSServer(t, (&fakeDNS{}).handler())
	o := newTestOptions(t, addr)

	// The httptest address plays the role of the scanned subdomain.
	services, verdict, ev := identifyCtx(srv.Listener.Addr().String(), newDomainCtx(o, nil, "x.test"))
	if verdict != VerdictVulnerable || len(services) != 1 || services[0] != "GITHUB" {
		t.Fatalf("services = %v verdict = %q, want [GITHUB] vulnerable", services, verdict)
	}
	if ev.HTTPStatus != 404 {
		t.Errorf("http status = %d, want 404 recorded as evidence", ev.HTTPStatus)
	}
	if len(ev.BodySHA1) != 12 {
		t.Errorf("body sha1 = %q, want a 12-char prefix", ev.BodySHA1)
	}
	if ev.BodyBytes != len(githubBody) {
		t.Errorf("body bytes = %d, want %d", ev.BodyBytes, len(githubBody))
	}
}

func TestMultiFingerprintJSON(t *testing.T) {
	addr := startTestDNSServer(t, pipelineFixture())
	pipelineHTTP(t)

	_, js := runPipeline(t, addr, 4)
	if !strings.Contains(js, `"services":["github","s3 bucket"]`) {
		t.Errorf("json = %s, want multi.site.test to carry both matched services", js)
	}
}

// captureStderr mirrors captureStdout for the summary/diagnostics stream.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	old := os.Stderr
	os.Stderr = w

	fn()

	w.Close()
	os.Stderr = old
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("reading captured stderr: %v", err)
	}
	return ansiRe.ReplaceAllString(string(data), "")
}
