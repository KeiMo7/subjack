package subjack

import (
	"crypto/tls"
	"time"

	"github.com/valyala/fasthttp"
)

var httpClient = &fasthttp.Client{
	TLSConfig: &tls.Config{InsecureSkipVerify: true},
}

// maxBodyBytes caps how much of a response body is kept for fingerprint
// matching. Bodies are never emitted to output; only a hash and length are.
const maxBodyBytes = 1 << 20

// httpResponse is a bounded view of an HTTP probe.
type httpResponse struct {
	body      []byte // truncated to maxBodyBytes
	status    int
	truncated bool
}

// httpProbeFunc is indirection so tests can route probes at fixtures.
var httpProbeFunc = httpProbe

// httpProbe fetches a URL and returns the (capped) body, the status code,
// and any transport error. Unlike the legacy httpGet, failures are visible
// to the caller instead of masquerading as an empty page.
func httpProbe(url string, ssl bool, timeout int) (*httpResponse, error) {
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	scheme := "http://"
	if ssl {
		scheme = "https://"
	}

	req.SetRequestURI(scheme + url)
	req.Header.Add("Connection", "close")

	if err := httpClient.DoTimeout(req, resp, time.Duration(timeout)*time.Second); err != nil {
		return nil, err
	}

	body := resp.Body()
	out := &httpResponse{status: resp.StatusCode()}
	n := len(body)
	if n > maxBodyBytes {
		n = maxBodyBytes
		out.truncated = true
	}
	out.body = make([]byte, n)
	copy(out.body, body[:n])
	return out, nil
}

// httpGet preserves the legacy API: it returns the body or an empty slice
// on any failure.
func httpGet(url string, ssl bool, timeout int) []byte {
	r, err := httpProbe(url, ssl, timeout)
	if err != nil {
		return nil
	}
	return r.body
}
