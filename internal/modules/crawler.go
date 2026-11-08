package modules

import (
	"net/url"
	"sort"
	"strings"

	"github.com/zapstiko/xsshunts/internal/models"
)

// Crawl discovers same-origin endpoints and forms starting from the seeds.
// URL deduplication ignores query values but remembers distinct parameter
// names so equivalent fuzzable endpoints are not scanned twice.
func Crawl(s *Session, seeds []string, depth, maxURLs int) []models.Target {
	if depth < 1 {
		depth = 1
	}
	key := func(raw string) string {
		u, err := url.Parse(raw)
		if err != nil {
			return raw
		}
		names := []string{}
		for k := range u.Query() {
			names = append(names, k)
		}
		sort.Strings(names)
		u.RawQuery = ""
		u.Fragment = ""
		return u.String() + "|" + strings.Join(names, ",")
	}

	visited := map[string]bool{}
	var queue []models.Target
	var out []models.Target

	push := func(raw string, newDepth int) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return
		}
		k := key(u.String())
		if visited[k] || len(out) >= maxURLs {
			return
		}
		visited[k] = true
		t := models.Target{URL: u.String(), Method: "get", Depth: newDepth}
		queue = append(queue, t)
		out = append(out, t)
	}

	for _, seed := range seeds {
		push(seed, 0)
	}

	for i := 0; i < len(queue) && i < maxURLs; i++ {
		current := queue[i]
		if current.Depth >= depth {
			continue
		}
		resp, err := s.HTTP.Get(current.URL, nil)
		if err != nil {
			continue
		}
		if len(resp.WAF) > 0 {
			s.AddWAF(resp.WAF)
		}
		base, berr := url.Parse(current.URL)
		if berr != nil {
			continue
		}
		for _, link := range parseFormLinks(resp.Body, current.URL) {
			lu, lerr := url.Parse(link)
			if lerr != nil {
				continue
			}
			lu.Scheme = base.Scheme
			lu.Fragment = ""
			if lu.Host != base.Host {
				continue
			}
			push(lu.String(), current.Depth+1)
			if len(out) >= maxURLs {
				break
			}
		}
	}
	return out
}
