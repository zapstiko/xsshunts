package modules

import (
	"fmt"
	"strings"

	"github.com/zapstiko/xsshunts/internal/models"
	"github.com/zapstiko/xsshunts/internal/payloads"
	"github.com/zapstiko/xsshunts/internal/utils"
)

// ScanPath injects payloads into URL path segments.
func ScanPath(s *Session, t models.Target, custom []string) {
	sets := AllVectorPayloads(custom)
	list := sets[models.ContextHTML]
	segs := pathSegmentCount(t.URL)
	positions := pathPositions(segs)
	s.Step("testing path injection with %d payload(s) across %d segment position(s)", len(list), len(positions))
	for _, pos := range positions {
		for _, raw := range list {
			rendered := payloads.Render(raw, utils.Token())
			s.Sleep(true)
			out := runPathPayload(s, t, pos, rendered)
			recordFinding(s, t, models.VectorPath, "path:"+posLabel(t.URL, pos), models.ContextHTML, rendered, out, nil)
			if out.Confirmed {
				break
			}
		}
	}
}

// runPathPayload tries payloads in the middle and appended to the path.
func runPathPayload(s *Session, t models.Target, pos int, payloadStr string) payloadOutcome {
	out := payloadOutcome{}

	// HTTP reflection (path injections only reflect if the server echoes them)
	target := injectPath(t.URL, pos, payloadStr)
	resp, err := s.HTTP.Get(target, nil)
	if err == nil && resp != nil {
		if len(resp.WAF) > 0 {
			s.AddWAF(resp.WAF)
		}
		if strings.Contains(resp.Body, payloadStr) {
			out.Candidate = true
			out.Evidence = snippetFor(resp.Body, payloadStr)
		}
	}
	if !out.Candidate && !s.BrowserAvailable() {
		return out
	}
	res, perr := s.Probe(target, nil, cookiesFor(s), "", 0)
	if perr == nil && res != nil && res.Dialog != nil {
		if token := extractToken(payloadStr); token != "" && strings.Contains(res.Dialog.Message, token) {
			out.Confirmed = true
			out.Dialog = res.Dialog.Message
		}
	}
	return out
}

// pathPositions returns middle and directory-rewrite indices.
func pathPositions(n int) []int {
	if n == 0 {
		return []int{0} // root: APPEND variant handled via injectPath(no segs) => "/payload"
	}
	seen := map[int]bool{}
	var out []int
	if n > 1 {
		seen[n/2] = true
		out = append(out, n/2)
		if !seen[n-1] {
			seen[n-1] = true
			out = append(out, n-1)
		}
	} else {
		seen[0] = true
		out = append(out, 0)
	}
	if !seen[n] {
		out = append(out, n) // appended segment
	}
	return out
}

// posLabel provides a stable report name for the injection position.
func posLabel(tURL string, pos int) string {
	_ = tURL
	return fmt.Sprint(pos)
}
