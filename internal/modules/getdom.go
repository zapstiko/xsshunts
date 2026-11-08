package modules

import (
	"github.com/zapstiko/xsshunts/internal/models"
	"github.com/zapstiko/xsshunts/internal/payloads"
	"github.com/zapstiko/xsshunts/internal/utils"
)

// ScanGet tests every mapped GET parameter with context-tuned payloads.
func ScanGet(s *Session, t models.Target, params []models.Param, custom []string) {
	sets := AllVectorPayloads(custom)
	for _, param := range params {
		if skip(s, param.Name) {
			continue
		}
		contextKind := param.Context
		if contextKind == "" {
			contextKind = models.ContextHTML
		}
		choose := resolveContext(contextKind)
		s.Step("testing GET param %q (context: %s) with %d payloads", param.Name, choose, len(sets[choose]))
		for _, raw := range sets[choose] {
			rendered := payloads.Render(raw, utils.Token())
			s.Sleep(true)
			out := runPayload(s, t, models.VectorGet, param.Name, contextKind, rendered, nil)
			recordFinding(s, t, models.VectorGet, param.Name, contextKind, rendered, out, nil)
			if out.Confirmed {
				break
			}
		}
	}
}

// resolveContext maps reflection contexts to payload sets.
func resolveContext(ctx string) string {
	switch ctx {
	case models.ContextAttribute:
		return models.ContextAttribute
	case models.ContextJavascript, "js":
		return models.ContextJavascript
	case models.ContextURL:
		return models.ContextURL
	case "css":
		return models.ContextHTML
	default:
		return models.ContextHTML
	}
}
