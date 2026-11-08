package modules

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/zapstiko/xsshunts/internal/browser"
	"github.com/zapstiko/xsshunts/internal/models"
	"github.com/zapstiko/xsshunts/internal/utils"
)

// payloadOutcome summarizes a single payload attempt at an injection point.
type payloadOutcome struct {
	Confirmed bool // dialog verified
	Candidate bool // mere reflection
	Evidence  string
	Dialog    string
}

// dialogURL builds the URL used by the browser probe for each vector.
func dialogURL(vector, tURL, param, payloadStr string) string {
	switch vector {
	case models.VectorGet:
		return buildQuery(tURL, param, payloadStr)
	case models.VectorPath:
		center := pathSegmentCount(tURL) / 2
		return injectPath(tURL, center, payloadStr)
	case models.VectorFragment:
		return tURL + "#" + fragmentEscape(payloadStr)
	default:
		return tURL
	}
}

// fragmentEscape encodes hash payloads (browsers keep fragment chars raw).
func fragmentEscape(p string) string {
	p = url.PathEscape(p)
	return strings.ReplaceAll(p, "%20", "%20")
}

// syntheticFormJS builds JavaScript that creates and submits a form carrying
// the payload in one field; used by the POST vector in the browser.
func syntheticFormJS(action string, method string, fields map[string]string) string {
	if method == "" {
		method = "post"
	}
	var parts []string
	for name, val := range fields {
		parts = append(parts, fmt.Sprintf(".addField(qs, %s, %s);", quoteJS(name), quoteJS(val)))
	}
	body := strings.Join(parts, "\n\t")
	return fmt.Sprintf(`(() => {
	const f = document.createElement('form');
	f.method = %s;
	f.action = %s;
	function addField(qs, name, value){
		const inp = document.createElement('input');
		inp.name = name;
		inp.value = value;
		f.appendChild(inp);
	}
	%s
	document.body.appendChild(f);
	try { f.requestSubmit(); } catch(e) { f.submit(); }
	return 'SUBMITTED';
})()`, quoteJS(strings.ToUpper(method)), quoteJS(action), body)
}

// quoteJS serializes a value for safe embedding inside generated JS.
func quoteJS(v string) string { return strconv.Quote(v) }

// runPayload drives one rendered payload against one injection point:
// HTTP reflection first, then the dialog-verification browser round trip.
func runPayload(s *Session, t models.Target, vector, param, contextKind, payloadStr string, extra map[string]string) payloadOutcome {
	out := payloadOutcome{}

	// 1) raw reflection evidence (works without a browser)
	resp, reflected := reflectProbe(s, t, vector, param, payloadStr, extra)
	if reflected {
		out.Candidate = true
		out.Evidence = snippetFor(resp.Body, payloadStr)
	}

	// 2) browser dialog probe
	if !reflected && !s.BrowserAvailable() {
		return out
	}
	var (
		res *browser.ProbeResult
		err error
	)
	switch vector {
	case models.VectorPost:
		fields := postFieldsFrom(t, param, payloadStr)
		js := syntheticFormJS(t.URL, firstNonEmpty(strings.ToLower(t.Method), "post"), fields)
		res, err = s.Probe("about:blank", extra, cookiesFor(s), js, 0)
	default:
		res, err = s.Probe(dialogURL(vector, t.URL, param, payloadStr), extra, cookiesFor(s), "", 0)
	}
	if err == nil && res != nil && res.Dialog != nil {
		token := extractToken(payloadStr)
		if strings.Contains(res.Dialog.Message, token) {
			out.Confirmed = true
			out.Dialog = res.Dialog.Message
		}
	}
	return out
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func cookiesFor(s *Session) map[string]string {
	return s.Opts.CookieMap()
}

// postFieldsFrom derives POST fields: user -d data if present, else a minimal
// single-field form.
func postFieldsFrom(t models.Target, param, payloadStr string) map[string]string {
	fields := map[string]string{}
	if t.Data != "" {
		if vals, err := url.ParseQuery(t.Data); err == nil {
			for k, vv := range vals {
				fields[k] = strings.Join(vv, ",")
			}
		}
	}
	if fields == nil {
		fields = map[string]string{}
	}
	fields[param] = payloadStr
	return fields
}

// recordFinding stores whichever confirmation level we reached.
func recordFinding(s *Session, t models.Target, vector, param, contextKind, payloadStr string, out payloadOutcome, extra map[string]string) {
	f := models.Finding{
		Method:    methodFor(vector),
		Vector:    vector,
		Parameter: param,
		Payload:   payloadStr,
		Context:   contextKind,
		Headers:   extra,
	}
	f.URL = dialogURL(vector, t.URL, param, payloadStr)
	if vector == models.VectorPost {
		f.URL = t.URL
	}
	if out.Confirmed {
		f.Confirmation = models.ConfirmDialog
		f.Dialog = out.Dialog
		f.Severity = "high"
		s.AddFinding(f)
		s.Good("confirmed XSS (dialog) via %s param %q | url: %s | payload: %s", vector, param, f.URL, payloadStr)
	} else if out.Candidate {
		f.Confirmation = models.ConfirmReflection
		f.Evidence = out.Evidence
		f.Severity = "potential"
		s.AddFinding(f)
		s.Candidate("payload mirrored (%s) param %q | url: %s | payload: %s | evidence: %s", vector, param, f.URL, payloadStr, out.Evidence)
	}
}

// extractToken recovers the canary embedded by payloads.Render.
func extractToken(payload string) string {
	i := strings.Index(payload, "'xsh")
	if i < 0 {
		return ""
	}
	sub := payload[i+1:]
	end := strings.Index(sub, "'")
	if end < 0 {
		return ""
	}
	return sub[:end]
}

// snippetFor returns a trimmed evidence window around the first found payload.
func snippetFor(body, payload string) string {
	raw := strings.ReplaceAll(payload, "&&", "&")
	i := strings.Index(body, raw)
	if i < 0 {
		return ""
	}
	start, end := i-32, i+len(payload)+32
	if start < 0 {
		start = 0
	}
	if end > len(body) {
		end = len(body)
	}
	return strings.ReplaceAll(body[start:end], "\n", " ")
}

// reflectProbe performs the HTTP round trip checking the fully rendered
// payload (matching both raw and slightly re-encoded forms).
func reflectProbe(s *Session, t models.Target, vector, param, payloadStr string, extra map[string]string) (*utils.Response, bool) {
	reqURL, reqBody, extraOut, err := injectIntoSource(vector, t.URL, t.Data, param, payloadStr, extra)
	if err != nil {
		return nil, false
	}
	var resp *utils.Response
	switch vector {
	case models.VectorPost:
		resp, err = s.HTTP.Do("POST", reqURL, reqBody, extraOut)
	case models.VectorHeader:
		resp, err = s.HTTP.Do("GET", reqURL, reqBody, extraOut)
	default:
		resp, err = s.HTTP.Do("GET", reqURL, "", extraOut)
	}
	if err != nil || resp == nil {
		return nil, false
	}
	if len(resp.WAF) > 0 {
		s.AddWAF(resp.WAF)
	}
	body := resp.Body
	if strings.Contains(body, payloadStr) || urlDecodedContains(body, payloadStr) {
		return resp, true
	}
	return resp, false
}

// urlDecodedContains loosens the match for double-encoded server behavior.
func urlDecodedContains(body, payload string) bool {
	decoded, err := url.QueryUnescape(payload)
	if err != nil || decoded == payload {
		return false
	}
	return strings.Contains(body, decoded)
}

func (p payloadOutcome) String() string {
	return fmt.Sprintf("confirmed=%v candidate=%v", p.Confirmed, p.Candidate)
}

var _ = strconv.Itoa
