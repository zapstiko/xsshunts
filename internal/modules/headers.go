package modules

import (
	"strings"

	"github.com/zapstiko/xsshunts/internal/models"
	"github.com/zapstiko/xsshunts/internal/payloads"
	"github.com/zapstiko/xsshunts/internal/utils"
)

// ScanHeader injects payloads into HTTP request headers. The Cookie header is
// delivered through real browser cookies so dialog confirmation works.
func ScanHeader(s *Session, t models.Target, custom []string) {
	names := s.Opts.HeaderScanNames()
	sets := AllVectorPayloads(custom)
	s.Step("testing %d HTTP header(s), %d payload(s) each", len(names), len(sets[models.ContextHTML]))
	for _, name := range names {
		if name == "Cookie" {
			scanCookieHeader(s, t, sets[models.ContextHTML], custom)
			continue
		}
		for _, raw := range sets[models.ContextHTML] {
			rendered := payloads.Render(raw, utils.Token())
			s.Sleep(true)
			out := runHeaderPayload(s, t, name, rendered)
			recordFinding(s, t, models.VectorHeader, name, models.ContextHTML, rendered, out, map[string]string{name: rendered})
			if out.Confirmed {
				break
			}
		}
	}
}

// runHeaderPayload sends one payload via one request header.
func runHeaderPayload(s *Session, t models.Target, name, payloadStr string) payloadOutcome {
	out := payloadOutcome{}
	resp, err := s.HTTP.Get(t.URL, map[string]string{name: payloadStr})
	if err == nil && resp != nil {
		if len(resp.WAF) > 0 {
			s.AddWAF(resp.WAF)
		}
		if strings.Contains(resp.Body, payloadStr) || urlDecodedContains(resp.Body, payloadStr) {
			out.Candidate = true
			out.Evidence = snippetFor(resp.Body, payloadStr)
		}
	}
	if !out.Candidate && !s.BrowserAvailable() {
		return out
	}
	res, perr := s.Probe(t.URL, map[string]string{name: payloadStr}, cookiesFor(s), "", 0)
	if perr == nil && res != nil && res.Dialog != nil {
		if token := extractToken(payloadStr); token != "" && strings.Contains(res.Dialog.Message, token) {
			out.Confirmed = true
			out.Dialog = res.Dialog.Message
		}
	}
	return out
}

// scanCookieHeader is the dedicated Cookie-header vector (browser-safe).
func scanCookieHeader(s *Session, t models.Target, list []string, custom []string) {
	for _, raw := range list {
		rendered := payloads.Render(raw, utils.Token())
		s.Sleep(true)
		out := payloadOutcome{}
		resp, err := s.HTTP.Get(t.URL, map[string]string{"Cookie": "xs=" + payloadMarker(rendered)})
		if err == nil && resp != nil && strings.Contains(resp.Body, rendered) {
			out.Candidate = true
			out.Evidence = snippetFor(resp.Body, rendered)
		}
		if s.BrowserAvailable() {
			cookies := cookiesFor(s)
			cookies["xs"] = payloadMarker(rendered)
			res, perr := s.Probe(t.URL, nil, cookies, "", 0)
			if perr == nil && res != nil && res.Dialog != nil {
				if token := extractToken(rendered); token != "" && strings.Contains(res.Dialog.Message, token) {
					out.Confirmed = true
					out.Dialog = res.Dialog.Message
				}
			}
		}
		recordFinding(s, t, models.VectorHeader, "Cookie", models.ContextHTML, rendered, out, nil)
		if out.Confirmed {
			break
		}
	}
}

// payloadMarker wraps the rendered payload so navigating with it as a cookie
// remains legal HTTP.
func payloadMarker(rendered string) string {
	return strings.ReplaceAll(rendered, ";", "%3B")
}

var _ = extractToken
