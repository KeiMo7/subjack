package subjack

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

//go:embed fingerprints.json
var fingerprintsJSON []byte

const (
	colorGreen  = "\033[32;1m"
	colorRed    = "\033[31;1m"
	colorYellow = "\033[33;1m"
	colorReset  = "\033[0m"
)

// maxLineLen bounds any single emitted line; longer content is truncated
// and visibly marked. Response bodies are never emitted at all.
const maxLineLen = 1024

type Result struct {
	Subdomain  string    `json:"subdomain"`
	Vulnerable bool      `json:"vulnerable"`
	Service    string    `json:"service,omitempty"`
	Services   []string  `json:"services,omitempty"`
	Domain     string    `json:"nonexist_domain,omitempty"`
	Verdict    string    `json:"verdict,omitempty"`
	Evidence   *Evidence `json:"evidence,omitempty"`
}

var outputMu sync.Mutex

// outputErrCount records output write failures across the process. The
// first failure is reported on stderr; Process turns any failure into a
// non-zero exit after the batch finishes so already-obtained conclusions
// are not lost.
var outputErrCount atomic.Int32

func noteOutputError(err error) {
	if outputErrCount.Add(1) == 1 {
		fmt.Fprintf(os.Stderr, "subjack: writing output failed: %v (conclusions are preserved on stdout)\n", err)
	}
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func truncateLine(s string) string {
	if len(s) <= maxLineLen {
		return s
	}
	return s[:maxLineLen] + "…[truncated]"
}

// renderFinding prints one finding to stdout and appends it to the output
// file. It is the single rendering path for both the legacy direct-print
// mode and the ordered emitter, so the text format is identical in both.
func renderFinding(f Finding, o *Options) {
	if f.main {
		renderMain(f, o)
		return
	}

	// Auxiliary check finding: "[SERVICE] detail".
	fmt.Printf("[%s%s%s] %s\n", colorGreen, f.Service, colorReset, truncateLine(f.Detail))
	if o.Output != "" {
		plain := fmt.Sprintf("[%s] %s\n", f.Service, truncateLine(f.Detail))
		if err := writeFinding(f, plain, o); err != nil {
			noteOutputError(err)
		}
	}
}

func renderMain(f Finding, o *Options) {
	switch f.Verdict {
	case VerdictVulnerable:
		for _, service := range f.Services {
			fmt.Printf("[%s%s%s] %s\n", colorGreen, service, colorReset, f.URL)
		}
	case VerdictNotVulnerable:
		if o.Verbose {
			fmt.Printf("[%sNot Vulnerable%s] %s\n", colorRed, colorReset, f.URL)
		}
	case VerdictUndetermined:
		if o.Verbose {
			fmt.Printf("[%sUndetermined%s] %s (%s)\n", colorYellow, colorReset, f.URL, truncateLine(f.Ev.Reason))
		}
	case VerdictSuppressed:
		if o.Verbose {
			fmt.Printf("[%sSuppressed%s] %s (%s)\n", colorYellow, colorReset, f.URL, truncateLine(f.Ev.Reason))
		}
	}

	if o.Output == "" {
		return
	}
	if err := writeFinding(f, mainPlainLine(f), o); err != nil {
		noteOutputError(err)
	}
}

// mainPlainLine renders the text-file form of a main finding.
func mainPlainLine(f Finding) string {
	switch f.Verdict {
	case VerdictVulnerable:
		var b strings.Builder
		for _, service := range f.Services {
			fmt.Fprintf(&b, "[%s] %s\n", service, f.URL)
		}
		return b.String()
	case VerdictUndetermined:
		return fmt.Sprintf("[Undetermined] %s (%s)\n", f.URL, truncateLine(f.Ev.Reason))
	case VerdictSuppressed:
		return fmt.Sprintf("[Suppressed] %s (%s)\n", f.URL, truncateLine(f.Ev.Reason))
	default:
		return fmt.Sprintf("[Not Vulnerable] %s\n", f.URL)
	}
}

// resultFor maps a finding to its JSON form, preserving the legacy field
// semantics (service lowercase, nonexist_domain for unregistered domains).
func resultFor(f Finding) Result {
	r := Result{
		Subdomain: strings.ToLower(f.URL),
		Evidence:  f.Ev,
	}
	if !f.main {
		r.Vulnerable = true
		r.Service = strings.ToLower(f.Service)
		r.Verdict = string(VerdictVulnerable)
		return r
	}

	r.Verdict = string(f.Verdict)
	switch f.Verdict {
	case VerdictVulnerable:
		r.Vulnerable = true
		service := f.Service
		if strings.HasPrefix(service, "DOMAIN AVAILABLE - ") {
			r.Service = "unregistered domain"
			r.Domain = strings.Split(service, " - ")[1]
		} else {
			r.Service = strings.ToLower(service)
		}
		if len(f.Services) > 1 {
			for _, s := range f.Services {
				r.Services = append(r.Services, strings.ToLower(s))
			}
		}
	}
	return r
}

// writeFinding appends one finding to the output file, using the streaming
// JSON writer when the process opened one.
func writeFinding(f Finding, plain string, o *Options) error {
	if strings.HasSuffix(o.Output, ".json") {
		if o.jw != nil {
			return o.jw.writeResult(resultFor(f))
		}
		return appendJSONResult(resultFor(f), o.Output)
	}
	return appendText(plain, o.Output)
}

func printResult(service, url string, o *Options) {
	if service != "" {
		colored := colorGreen + service + colorReset
		fmt.Printf("[%s] %s\n", colored, url)
	} else if o.Verbose {
		fmt.Printf("[%sNot Vulnerable%s] %s\n", colorRed, colorReset, url)
	}

	if o.Output != "" {
		if service != "" {
			plain := fmt.Sprintf("[%s] %s\n", service, url)
			if err := writeOutput(service, url, plain, o.Output); err != nil {
				noteOutputError(err)
			}
		} else {
			plain := fmt.Sprintf("[Not Vulnerable] %s\n", url)
			if err := writeOutput("", url, plain, o.Output); err != nil {
				noteOutputError(err)
			}
		}
	}
}

func initOutput(path string) error {
	if strings.HasSuffix(path, ".json") {
		return os.WriteFile(path, []byte("[]"), 0600)
	}
	return os.WriteFile(path, nil, 0600)
}

func writeOutput(service, url, plain, output string) error {
	outputMu.Lock()
	defer outputMu.Unlock()

	if strings.HasSuffix(output, ".json") {
		return appendJSON(service, url, output)
	}
	return appendText(plain, output)
}

func appendText(text, path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(text)
	return err
}

func appendJSON(service, url, path string) error {
	return appendJSONResult(legacyResult(service, url), path)
}

// legacyResult reproduces the original JSON mapping for the writeOutput
// compatibility path.
func legacyResult(service, url string) Result {
	if strings.HasPrefix(service, "DOMAIN AVAILABLE - ") {
		return Result{
			Subdomain:  strings.ToLower(url),
			Vulnerable: true,
			Service:    "unregistered domain",
			Domain:     strings.Split(service, " - ")[1],
		}
	}
	if service != "" {
		return Result{
			Subdomain:  strings.ToLower(url),
			Vulnerable: true,
			Service:    strings.ToLower(service),
		}
	}
	return Result{
		Subdomain:  strings.ToLower(url),
		Vulnerable: false,
	}
}

// appendJSONResult appends one entry by read-modify-write. It is kept for
// the compatibility path; the pipeline uses jsonStreamWriter instead, which
// is O(1) per entry.
func appendJSONResult(r Result, path string) error {
	var data []Result
	if existing, err := os.ReadFile(path); err == nil {
		json.Unmarshal(existing, &data)
	}
	data = append(data, r)

	out, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0600)
}

// jsonStreamWriter writes a JSON array incrementally so output cost stays
// O(1) per entry regardless of input size. The final file is a plain JSON
// array, identical in shape to what appendJSON produced.
type jsonStreamWriter struct {
	f     *os.File
	first bool
}

func newJSONStreamWriter(path string) (*jsonStreamWriter, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, err
	}
	if _, err := f.WriteString("["); err != nil {
		f.Close()
		return nil, err
	}
	return &jsonStreamWriter{f: f, first: true}, nil
}

func (w *jsonStreamWriter) writeResult(r Result) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if !w.first {
		if _, err := w.f.WriteString(","); err != nil {
			return err
		}
	}
	w.first = false
	_, err = w.f.Write(data)
	return err
}

func (w *jsonStreamWriter) close() error {
	if _, err := w.f.WriteString("]"); err != nil {
		w.f.Close()
		return err
	}
	return w.f.Close()
}

func loadFingerprints() []Fingerprint {
	var data []Fingerprint
	if err := json.Unmarshal(fingerprintsJSON, &data); err != nil {
		log.Fatalln(err)
	}
	return data
}

// summaryCounts tallies per-domain verdicts for the end-of-run summary.
type summaryCounts struct {
	total         int
	vulnerable    int
	notVulnerable int
	undetermined  int
	suppressed    int
	skipped       int
	fallbacks     int
}

// emitter renders per-domain reports in input order. Reports may complete
// out of order across workers; the emitter buffers them until every earlier
// sequence number has been rendered, so concurrent runs are deterministic.
type emitter struct {
	o        *Options
	mu       sync.Mutex
	next     int
	pending  map[int]*report
	counts   summaryCounts
	onRender func()
}

func newEmitter(o *Options) *emitter {
	return &emitter{o: o, pending: make(map[int]*report)}
}

func (em *emitter) emit(seq int, rep *report) {
	em.mu.Lock()
	defer em.mu.Unlock()
	em.pending[seq] = rep
	for {
		r, ok := em.pending[em.next]
		if !ok {
			return
		}
		delete(em.pending, em.next)
		em.render(r)
		em.next++
		if em.onRender != nil {
			em.onRender()
		}
	}
}

func (em *emitter) render(rep *report) {
	em.counts.total++
	vulnerable := false
	for _, f := range rep.aux {
		renderFinding(f, em.o)
		if f.Verdict == VerdictVulnerable {
			vulnerable = true
		}
		em.countEvidence(f.Ev)
	}
	if rep.main != nil {
		renderFinding(*rep.main, em.o)
		em.countEvidence(rep.main.Ev)
		switch rep.main.Verdict {
		case VerdictVulnerable:
			vulnerable = true
		case VerdictNotVulnerable:
			em.counts.notVulnerable++
		case VerdictUndetermined:
			em.counts.undetermined++
		case VerdictSuppressed:
			em.counts.suppressed++
		}
	}
	if vulnerable {
		em.counts.vulnerable++
	} else if rep.main == nil {
		em.counts.skipped++
	}
}

func (em *emitter) countEvidence(ev *Evidence) {
	if ev != nil && ev.Fallback {
		em.counts.fallbacks++
	}
}

// printSummary writes the run tally to stderr so stdout parsing is
// unaffected. Undetermined is counted separately from not-vulnerable.
func (em *emitter) printSummary() {
	c := em.counts
	fmt.Fprintf(os.Stderr,
		"[summary] total=%d vulnerable=%d not_vulnerable=%d undetermined=%d suppressed=%d skipped=%d resolver_fallbacks=%d\n",
		c.total, c.vulnerable, c.notVulnerable, c.undetermined, c.suppressed, c.skipped, c.fallbacks)
}
