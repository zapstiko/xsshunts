package modules

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/html"

	"github.com/zapstiko/xsshunts/internal/models"
	"github.com/zapstiko/xsshunts/internal/utils"
)

// Discovery is the outcome of the mining step for one target.
type Discovery struct {
	GetParams  []models.Param
	PostParams []models.Param // -d data fields discovered manually
	Forms      []*models.Form
	JSVars     []models.Param
}

var windowVarRe = regexp.MustCompile(`(?:window\.[A-Za-z_$][\w$]*\s*=[^;\n]{0,80})|(?:\.innerHTML\s*=)|(?:document\.write)`)

// Discover runs mining: input URL params, links, forms, window JS variables,
// then hidden parameter wordlist probing.
func Discover(s *Session, t models.Target) *Discovery {
	d := &Discovery{}
	forced := s.Opts.ForcedContexts()

	// 1) explicit -p parameters always win
	for name, ctx := range forced {
		kind := models.VectorGet
		seen := false
		for _, p := range d.GetParams {
			if p.Name == name {
				seen = true
			}
		}
		if !seen {
			d.GetParams = append(d.GetParams, models.Param{Name: name, Source: "manual", Context: ctx})
			_ = kind
		}
	}

	// 2) params already on the target URL
	if u, err := url.Parse(t.URL); err == nil {
		for name := range u.Query() {
			if d.has(name) {
				continue
			}
			ctx := forced[name]
			d.GetParams = append(d.GetParams, models.Param{Name: name, Value: u.Query().Get(name), Source: "get", Context: ctx})
		}
	}

	// 3) mines from the live page: links, forms, window variables
	resp, err := s.HTTP.Get(t.URL, nil)
	if err != nil {
		s.Verbose("[!] mining fetch failed for %s: %v", t.URL, err)
		return d
	}
	if len(resp.WAF) > 0 {
		s.AddWAF(resp.WAF)
	}
	extraURLs := parseFormLinks(resp.Body, t.URL)
	for _, cand := range extraURLs {
		if u, err := url.Parse(cand); err == nil {
			for name := range u.Query() {
				if d.has(name) {
					continue
				}
				d.GetParams = append(d.GetParams, models.Param{Name: name, Source: "link", Context: forced[name]})
			}
		}
	}
	d.Forms = parseForms(resp.Body, t.URL)
	for _, f := range d.Forms {
		for _, field := range f.Fields {
			if field.Type == "submit" || field.Type == "hidden" && strings.ContainsAny(field.Value, "?&#") {
				continue
			}
			if d.has(field.Name) {
				continue
			}
			d.PostParams = append(d.PostParams, models.Param{Name: field.Name, Value: field.Value, Source: "form"})
		}
	}
	for _, m := range windowVarRe.FindAllString(resp.Body, 24) {
		name := extractWindowVarName(m)
		if name != "" && !d.has(name) {
			d.JSVars = append(d.JSVars, models.Param{Name: name, Value: m, Source: "jsvar"})
		}
	}

	// 4) hidden parameter probing with the wordlist
	excluded := s.Opts.ExcludedMap()
	words := s.LoadWordlist()
	for _, word := range words {
		if strings.Contains(word, "#") {
			continue
		}
		if d.has(word) || excluded[word] {
			continue
		}
		canary := utils.Token()
		probe := buildQuery(t.URL, word, canary)
		resp, perr := s.HTTP.Get(probe, nil)
		if perr != nil {
			continue
		}
		if len(resp.WAF) > 0 {
			s.AddWAF(resp.WAF)
		}
		if strings.Contains(resp.Body, canary) {
			param := models.Param{Name: word, Source: "hidden", Context: forced[word]}
			d.GetParams = append(d.GetParams, param)
			s.Info("  %s hidden parameter %q reflects the wordlist canary", utils.C(utils.Blue, "[mine]"), word)
		}
	}
	return d
}

func (d *Discovery) has(name string) bool {
	for _, p := range d.GetParams {
		if p.Name == name {
			return true
		}
	}
	for _, p := range d.PostParams {
		if p.Name == name {
			return true
		}
	}
	return false
}

func extractWindowVarName(stmt string) string {
	stmt = strings.TrimSpace(stmt)
	if strings.HasPrefix(stmt, "window.") {
		stmt = strings.TrimPrefix(stmt, "window.")
		if i := strings.Index(stmt, "="); i > 0 {
			stmt = strings.TrimSpace(stmt[:i])
		}
		return stmt
	}
	return ""
}

// parseFormLinks returns every href target on the page.
func parseFormLinks(body string, baseURL string) []string {
	root, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "a" {
			for _, a := range n.Attr {
				if strings.EqualFold(a.Key, "href") && a.Val != "" && !strings.HasPrefix(a.Val, "#") {
					if resolved := resolve(baseURL, a.Val); resolved != "" && !seen[resolved] {
						seen[resolved] = true
						out = append(out, resolved)
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(root)
	return out
}

// parseForms parses every <form> with its controls.
func parseForms(body string, baseURL string) []*models.Form {
	root, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return nil
	}
	var forms []*models.Form
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" {
			f := &models.Form{BaseURL: baseURL, Method: "get"}
			for _, a := range n.Attr {
				switch strings.ToLower(a.Key) {
				case "action":
					f.Action = resolve(baseURL, a.Val)
				case "method":
					if m := strings.ToLower(strings.TrimSpace(a.Val)); m == "post" {
						f.Method = "post"
					}
				}
			}
			if f.Action == "" {
				f.Action = baseURL
			}
			f.Fields = extractControlFields(n)
			forms = append(forms, f)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(root)
	return forms
}

func extractControlFields(formNode *html.Node) []models.FormField {
	var fields []models.FormField
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "input":
				f := models.FormField{Type: "text"}
				var name, value string
				for _, a := range n.Attr {
					switch strings.ToLower(a.Key) {
					case "name":
						name = a.Val
					case "value":
						value = a.Val
					case "type":
						f.Type = strings.ToLower(a.Val)
					}
				}
				if name != "" {
					f.Name = name
					f.Value = value
					fields = append(fields, f)
				}
			case "textarea", "select":
				var name string
				for _, a := range n.Attr {
					if strings.EqualFold(a.Key, "name") {
						name = a.Val
					}
				}
				if name != "" {
					fields = append(fields, models.FormField{Name: name, Type: n.Data})
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(formNode)
	return fields
}

func resolve(base, ref string) string {
	if ref == "" || strings.HasPrefix(ref, "javascript:") || strings.HasPrefix(ref, "mailto:") || strings.HasPrefix(ref, "tel:") || strings.HasPrefix(ref, "#") {
		return ""
	}
	bu, err := url.Parse(base)
	if err != nil {
		return ""
	}
	ru, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	res := bu.ResolveReference(ru)
	return res.String()
}

var _ = fmt.Sprintf
