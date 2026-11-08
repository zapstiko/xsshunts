package modules

import (
	"net/url"

	"github.com/zapstiko/xsshunts/internal/models"
	"github.com/zapstiko/xsshunts/internal/payloads"
	"github.com/zapstiko/xsshunts/internal/utils"
)

// ScanPost tests POST forms: -d data fields override discovered forms.
func ScanPost(s *Session, t models.Target, forms []*models.Form, custom []string) {
	sets := AllVectorPayloads(custom)
	dataFields := collectDataFields(t.Data)

	if len(dataFields) > 0 {
		for _, param := range dataFields {
			if skip(s, param) {
				continue
			}
			s.Step("testing POST field %q with %d payloads", param, len(sets[models.ContextHTML]))
			for _, raw := range sets[models.ContextHTML] {
				rendered := payloads.Render(raw, utils.Token())
				s.Sleep(true)
				out := runPayload(s, t, models.VectorPost, param, models.ContextHTML, rendered, nil)
				recordFinding(s, t, models.VectorPost, param, models.ContextHTML, rendered, out, nil)
				if out.Confirmed {
					break
				}
			}
		}
		return
	}

	for _, form := range forms {
		for _, field := range form.Fields {
			if field.Type == "submit" || field.Type == "button" || field.Type == "file" || skip(s, field.Name) || field.Name == "" {
				continue
			}
			formTarget := models.Target{Method: form.Method, URL: t.URL, Data: t.Data}
			if form.Method == "post" {
				formTarget.URL = firstNonEmpty(form.Action, t.URL)
			}
			s.Step("testing form %s field %q with %d payloads", form.Method, field.Name, len(sets[models.ContextHTML]))
			for _, raw := range sets[models.ContextHTML] {
				rendered := payloads.Render(raw, utils.Token())
				s.Sleep(true)
				var out payloadOutcome
				if form.Method == "post" {
					out = runPayload(s, formTarget, models.VectorPost, field.Name, models.ContextHTML, rendered, nil)
					recordFinding(s, formTarget, models.VectorPost, field.Name, models.ContextHTML, rendered, out, nil)
				} else {
					out = runPayload(s, formTarget, models.VectorGet, field.Name, models.ContextHTML, rendered, nil)
					recordFinding(s, formTarget, models.VectorGet, field.Name, models.ContextHTML, rendered, out, nil)
				}
				if out.Confirmed {
					break
				}
			}
		}
	}
}

// collectDataFields parses -d into field names.
func collectDataFields(data string) []string {
	vals, err := url.ParseQuery(data)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(vals))
	for name := range vals {
		names = append(names, name)
	}
	return names
}
