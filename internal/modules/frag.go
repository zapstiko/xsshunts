package modules

import (
	"strings"

	"github.com/zapstiko/xsshunts/internal/models"
	"github.com/zapstiko/xsshunts/internal/payloads"
	"github.com/zapstiko/xsshunts/internal/utils"
)

// ScanFragment tests URL hash fragments against SPA routers and DOM sinks.
// Fragments never reach the server, so this vector is browser-only; without a
// browser it is skipped with a warning.
func ScanFragment(s *Session, t models.Target, custom []string) {
	if !s.BrowserAvailable() {
		s.Warn("vector fragment requires the browser; skipping this target")
		return
	}
	sets := AllVectorPayloads(custom)
	list := sets[models.ContextHTML]
	s.Step("testing fragment injection with %d payloads", len(list))
	for _, raw := range list {
		rendered := payloads.Render(raw, utils.Token())
		s.Sleep(true)
		target := t.URL + "#" + fragmentEscape(rendered)
		token := extractToken(rendered)
		res, err := s.Probe(target, nil, cookiesFor(s), "", 0)
		if err != nil {
			s.Verbose("[debug] fragment probe failed: %v", err)
			continue
		}
		ev := ""
		confirmed := false
		if res.Dialog != nil && strings.Contains(res.Dialog.Message, token) {
			confirmed = true
		} else if res.HTML != "" && (strings.Contains(res.HTML, rendered) || strings.Contains(res.HTML, raw)) {
			ev = snippetFor(res.HTML, rendered)
		}
		out := payloadOutcome{Confirmed: confirmed, Evidence: ev}
		if confirmed {
			out.Dialog = res.Dialog.Message
		}
		recordFinding(s, t, models.VectorFragment, "fragment", models.ContextHTML, rendered, out, nil)
		if confirmed {
			break
		}
	}
}
