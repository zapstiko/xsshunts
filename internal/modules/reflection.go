package modules

import (
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/net/html"

	"github.com/zapstiko/xsshunts/internal/models"
	"github.com/zapstiko/xsshunts/internal/payloads"
	"github.com/zapstiko/xsshunts/internal/utils"
)

// Special characters probed for the character reflection matrix.
const specialChars = "'\"<>/;(){}=`"

var escapedForms = map[string]string{
	`"`: "&quot;",
	`'`: "&#39;",
	`<`: "&lt;",
	`>`: "&gt;",
	`(`: "&#40;",
	`)`: "&#41;",
}

// occurrence describes one canary location found in a response.
type occurrence struct {
	Context string
	Tag     string
	Attr    string
	Raw     string
}

// classify locates every canary position and maps it to its syntactic context
// with the x/net/html tokenizer (script/style raw text, attributes, comments).
func classify(body string, canary string) []occurrence {
	tk := html.NewTokenizer(strings.NewReader(body))
	var out []occurrence
	inScript := false
	lastStart := ""
	for {
		switch tk.Next() {
		case html.ErrorToken:
			return out
		case html.TextToken:
			text := string(tk.Text())
			if strings.Contains(text, canary) {
				ctx := models.ContextHTML
				tag := ""
				if inScript {
					ctx = models.ContextJavascript
					tag = "script"
				} else if lastStart == "style" {
					ctx = "css"
					tag = "style"
				}
				out = append(out, occurrence{Context: ctx, Tag: tag, Raw: snippet(text, canary)})
			}
		case html.StartTagToken, html.SelfClosingTagToken:
			name, _ := tk.TagName()
			lastStart = strings.ToLower(string(name))
			inScript = lastStart == "script"
			if lastStart != "script" && lastStart != "style" {
				tok := tk.Token()
				for _, attr := range tok.Attr {
					if strings.Contains(attr.Val, canary) {
						out = append(out, occurrence{
							Context: models.ContextAttribute,
							Tag:     lastStart,
							Attr:    strings.ToLower(attr.Key),
							Raw:     snippet(attr.Val, canary),
						})
					}
				}
			}
		case html.EndTagToken:
			name, _ := tk.TagName()
			if strings.EqualFold(string(name), "script") {
				inScript = false
			}
		}
	}
}

// snippet builds compact evidence surrounding the canary.
func snippet(s, canary string) string {
	i := strings.Index(s, canary)
	if i < 0 {
		return ""
	}
	start, end := i-24, i+len(canary)+24
	if start < 0 {
		start = 0
	}
	if end > len(s) {
		end = len(s)
	}
	return "…" + strings.ReplaceAll(s[start:end], "\n", " ") + "…"
}

// buildQuery renders a URL with one query param replaced/appended.
func buildQuery(rawurl, name, value string) string {
	u, err := url.Parse(rawurl)
	if err != nil {
		return rawurl
	}
	q := u.Query()
	q.Set(name, value)
	u.RawQuery = q.Encode()
	return u.String()
}

// injectPath replaces one URL path segment (apiURL /a/b/c => /a/b/PAYLOAD).
func injectPath(rawurl string, segmentIndex int, payload string) string {
	u, err := url.Parse(rawurl)
	if err != nil {
		return rawurl
	}
	segs := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(segs) == 0 || (len(segs) == 1 && segs[0] == "") {
		u.Path = "/" + payload
		u.RawPath = ""
		return u.String()
	}
	if segmentIndex >= 0 && segmentIndex < len(segs) {
		segs[segmentIndex] = payload
	}
	u.Path = "/" + strings.Join(segs, "/")
	u.RawPath = ""
	return u.String()
}

// pathSegmentCount returns the number of path segments in rawurl.
func pathSegmentCount(rawurl string) int {
	u, err := url.Parse(rawurl)
	if err != nil {
		return 0
	}
	segs := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(segs) == 1 && segs[0] == "" {
		return 0
	}
	return len(segs)
}

// buildPostBody replaces one key inside a raw form-encoded body.
func buildPostBody(rawBody, name, value string) url.Values {
	vals, err := url.ParseQuery(rawBody)
	if err != nil {
		vals = url.Values{}
	}
	vals.Set(name, value)
	return vals
}

// injectIntoSource builds the request for reflection probes.
func injectIntoSource(source, rawurl, body, name, value string, headerExtra map[string]string) (reqURL, reqBody string, extra map[string]string, err error) {
	switch source {
	case models.VectorGet:
		return buildQuery(rawurl, name, value), "", nil, nil
	case models.VectorPost:
		v := buildPostBody(body, name, value)
		return rawurl, v.Encode(), nil, nil
	case models.VectorPath:
		center := pathSegmentCount(rawurl) / 2
		return injectPath(rawurl, center, value), body, nil, nil
	case models.VectorHeader:
		extra = map[string]string{}
		for k, v := range headerExtra {
			extra[k] = v
		}
		extra[name] = value
		return rawurl, body, extra, nil
	default:
		return rawurl, body, nil, fmt.Errorf("unknown source %s", source)
	}
}

// charMatrix classifies each special char as allowed/escaped/filtered.
func charMatrix(respBody string, canary string) (allowed, escaped, filtered []string) {
	idx := strings.Index(respBody, canary)
	if idx < 0 {
		return nil, nil, specialCharList()
	}
	end := idx + len(canary) + len(specialChars) + 24
	if end > len(respBody) {
		end = len(respBody)
	}
	window := respBody[idx:end]
	joined := strings.ToLower(window)
	for _, ch := range specialCharList() {
		switch {
		case strings.Contains(window, ch):
			allowed = append(allowed, ch)
		case escapedForms[ch] != "" && strings.Contains(joined, escapedForms[ch]):
			escaped = append(escaped, ch)
		default:
			filtered = append(filtered, ch)
		}
	}
	return allowed, escaped, filtered
}

func specialCharList() []string {
	out := make([]string, 0, len(specialChars))
	for _, r := range specialChars {
		out = append(out, string(r))
	}
	return out
}

// AnalyzeReflection probes one parameter at one injection source with a
// canary token, classifies the context, and builds the character matrix.
// Returns (nil, nil) when the target did not mirror the canary.
func AnalyzeReflection(s *Session, t models.Target, source, param, forcedCtx string) (*models.Reflection, error) {
	canary := utils.Token()
	reqURL, reqBody, extra, err := injectIntoSource(source, t.URL, t.Data, param, canary, nil)
	if err != nil {
		return nil, err
	}
	var resp *utils.Response
	switch source {
	case models.VectorPost:
		resp, err = s.HTTP.Do("POST", reqURL, reqBody, extra)
	default:
		resp, err = s.HTTP.Do("GET", reqURL, "", extra)
	}
	if err != nil {
		return nil, err
	}
	if len(resp.WAF) > 0 {
		s.AddWAF(resp.WAF)
	}
	occ := classify(resp.Body, canary)
	if len(occ) == 0 {
		return nil, nil
	}
	best := occ[0]
	for _, o := range occ {
		tagNote := o.Tag != "" || o.Attr != ""
		startTag := o.Context == models.ContextHTML && o.Tag != ""
		if tagNote && !startTag {
			best = o
		}
	}
	r := &models.Reflection{
		URL:     reqURL,
		Param:   param,
		Source:  source,
		Context: best.Context,
		Tag:     best.Tag,
		Attr:    best.Attr,
	}
	if best.Context == models.ContextAttribute && best.Attr != "" && isNavAttr(best.Tag, best.Attr) {
		r.Context = models.ContextURL
	}
	if forcedCtx != "" {
		r.Context = forcedCtx
	}
	r.Allowed, r.Escaped, r.Filtered = charMatrix(resp.Body, canary)
	return r, nil
}

func isNavAttr(tag, attr string) bool {
	if attr != "href" && attr != "src" && attr != "action" && attr != "formaction" && attr != "data" && attr != "srcdoc" {
		return false
	}
	return tag != "script" && tag != "img"
}

// Describe renders the reflection summary line, e.g.
// "reflects in html context (tag: body)".
func Describe(r *models.Reflection) string {
	tag := ""
	if r.Tag != "" {
		tag = fmt.Sprintf(" (tag: %s", r.Tag)
		if r.Attr != "" {
			tag += ", attr: " + r.Attr
		}
		tag += ")"
	}
	return fmt.Sprintf("reflects in %s context%s", r.Context, tag)
}

// MatrixLine renders the character matrix summary.
func MatrixLine(r *models.Reflection) string {
	return fmt.Sprintf("character matrix: allowed [%s] | escaped [%s] | filtered [%s]",
		strings.Join(r.Allowed, ""), strings.Join(r.Escaped, ""), strings.Join(r.Filtered, ""))
}

// AllVectorPayloads returns the per-context payload sets, honoring a custom
// --payload-file override.
func AllVectorPayloads(custom []string) map[string][]string {
	out := map[string][]string{}
	if len(custom) > 0 {
		for _, ctx := range []string{models.ContextHTML, models.ContextAttribute, models.ContextJavascript, models.ContextURL, "css", models.ContextUnknown} {
			out[ctx] = custom
		}
		return out
	}
	for _, ctx := range []string{models.ContextHTML, models.ContextAttribute, models.ContextJavascript, models.ContextURL, "css", models.ContextUnknown} {
		out[ctx] = payloads.ByContext(ctx)
	}
	return out
}
