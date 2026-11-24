package subjack

import (
	"fmt"
	"math/rand/v2"
	"net"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// wildcardInfo describes whether the parent zone of a subdomain answers
// queries for arbitrary names (wildcard DNS). Probe results are cached per
// parent zone on Options.
type wildcardInfo struct {
	parent   string
	probe    string // the random name used to detect the wildcard
	wildcard bool
	ips      []string // sorted A records the probe resolved to
}

// parentDomain returns the parent zone used for wildcard probing: the
// subdomain with its first label dropped. IPs, host:port inputs, and names
// with fewer than three labels are not probed.
func parentDomain(subdomain string) string {
	if strings.Contains(subdomain, ":") || net.ParseIP(subdomain) != nil {
		return ""
	}
	labels := strings.Split(strings.TrimSuffix(subdomain, "."), ".")
	if len(labels) < 3 {
		return ""
	}
	return strings.Join(labels[1:], ".")
}

// wildcardInfoFor detects (once per parent zone) whether arbitrary names
// under the subdomain's parent resolve. Results are cached on Options.
func (dc *domainCtx) wildcardInfoFor(subdomain string) *wildcardInfo {
	parent := parentDomain(subdomain)
	if parent == "" {
		return nil
	}
	if v, ok := dc.o.wildcardCache.Load(parent); ok {
		return v.(*wildcardInfo)
	}

	info := &wildcardInfo{parent: parent}
	info.probe = fmt.Sprintf("subjack-wc-%d.%s", rand.Uint32(), parent)

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(info.probe), dns.TypeA)
	res := dc.exchange(msg)
	if res.status == statusOK {
		for _, a := range res.msg.Answer {
			if t, ok := a.(*dns.A); ok {
				info.ips = append(info.ips, t.A.String())
			}
		}
		sort.Strings(info.ips)
		info.wildcard = len(info.ips) > 0
	}

	dc.o.wildcardCache.Store(parent, info)
	return info
}
