package subjack

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"sync"
)

type Options struct {
	Domain       string
	Wordlist     string
	Threads      int
	Timeout      int
	Output       string
	Ssl          bool
	All          bool
	Verbose      bool
	Manual       bool
	CheckNS      bool
	CheckAR      bool
	CheckAXFR    bool
	CheckMail    bool
	CheckSRV     bool
	ResolverList string
	Stdin        bool
	// MaxQueries caps the number of DNS exchanges a single domain may
	// cause, including retries. Zero uses the default budget.
	MaxQueries    int
	fingerprints  []Fingerprint
	resolvers     []string
	sem           chan struct{}
	wildcardCache sync.Map
	jw            *jsonStreamWriter
	// checkAvailable overrides domain-availability lookups; used by tests.
	checkAvailable func(domain string) bool
}

// Process runs the scan and returns the process exit code: 0 on success, 1
// if the output file could not be written (conclusions are still printed).
func Process(o *Options) int {
	var list []string
	var err error

	if o.Threads <= 0 {
		o.Threads = 10
	}
	if o.Timeout <= 0 {
		o.Timeout = 10
	}

	if len(o.Domain) > 0 {
		list = append(list, o.Domain)
	} else if o.Wordlist != "" {
		list, err = readLines(o.Wordlist)
		if err != nil {
			log.Fatalln(err)
		}
	}

	o.fingerprints = loadFingerprints()

	outputOK := true
	if o.Output != "" {
		if err := initOutput(o.Output); err != nil {
			// Do not abort the batch: report and keep conclusions on
			// stdout, then exit non-zero at the end.
			noteOutputError(err)
			outputOK = false
		} else if hasJSONSuffix(o.Output) {
			if jw, err := newJSONStreamWriter(o.Output); err != nil {
				noteOutputError(err)
				outputOK = false
			} else {
				o.jw = jw
			}
		}
	}

	if o.ResolverList != "" {
		entries, err := readLines(o.ResolverList)
		if err != nil {
			log.Fatalln(err)
		}
		valid, invalid := validateResolvers(entries)
		for _, bad := range invalid {
			fmt.Fprintf(os.Stderr, "subjack: ignoring invalid resolver entry %q\n", bad)
		}
		if len(valid) == 0 && len(invalid) > 0 {
			fmt.Fprintf(os.Stderr, "subjack: no usable resolvers in %s; using default resolver %s\n",
				o.ResolverList, defaultResolver)
		}
		o.resolvers = valid
	}

	o.sem = make(chan struct{}, o.Threads)

	em := newEmitter(o)

	// The window bounds how many domains may be in flight or waiting to be
	// rendered. The feeder blocks when it is full, so peak memory stays
	// proportional to the window — not to the input size — while the
	// emitter preserves input order.
	window := make(chan struct{}, o.Threads*4+64)
	em.onRender = func() { <-window }

	type task struct {
		seq int
		url string
	}
	tasks := make(chan task, o.Threads)
	wg := new(sync.WaitGroup)

	for i := 0; i < o.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range tasks {
				rep := runDomain(t.url, newDomainCtx(o, &report{}, t.url))
				em.emit(t.seq, rep)
			}
		}()
	}

	seq := 0
	feed := func(url string) {
		window <- struct{}{}
		tasks <- task{seq: seq, url: url}
		seq++
	}

	if o.Stdin {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			feed(scanner.Text())
		}
	} else {
		for _, u := range list {
			feed(u)
		}
	}

	close(tasks)
	wg.Wait()

	if o.jw != nil {
		if err := o.jw.close(); err != nil {
			noteOutputError(err)
			outputOK = false
		}
		o.jw = nil
	}

	em.printSummary()

	if !outputOK {
		return 1
	}
	return 0
}

func hasJSONSuffix(path string) bool {
	return len(path) > 5 && path[len(path)-5:] == ".json"
}
