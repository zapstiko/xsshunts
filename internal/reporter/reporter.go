// Package reporter renders consent-friendly JSON/HTML reports and the console
// summary for a finished audit.
package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"html/template"
	"time"

	"github.com/zapstiko/xsshunts/internal/config"
	"github.com/zapstiko/xsshunts/internal/models"
	"github.com/zapstiko/xsshunts/internal/utils"
)

// Report aggregates every outcome of a scan.
type Report struct {
	Tool         string             `json:"tool"`
	Version      string             `json:"version"`
	GeneratedAt  time.Time          `json:"generated_at"`
	Targets      []string           `json:"targets"`
	Parameters   int                `json:"parameters_tested"`
	Reflections  int                `json:"reflections_observed"`
	WAF          []string           `json:"waf_detected,omitempty"`
	Confirmed    []*models.Finding  `json:"confirmed"`  // browser dialog verified
	Candidates   []*models.Finding  `json:"candidates"` // reflection only
}

// New creates an empty report.
func New() *Report {
	return &Report{Tool: "xsshunts", Version: config.Version, GeneratedAt: time.Now()}
}

// Count helpers.

// AddConfirmed records a browser-verified finding.
func (r *Report) AddConfirmed(f *models.Finding) { r.Confirmed = append(r.Confirmed, f) }

// AddCandidate records a reflection-only finding.
func (r *Report) AddCandidate(f *models.Finding) { r.Candidates = append(r.Candidates, f) }

// Stats prints the final console summary block.
func (r *Report) Stats() {
	line := strings.Repeat("=", 74)
	fmt.Println(utils.C(utils.Gray, line))
	fmt.Printf("%s\n", utils.C(utils.Bold, "scan summary"))
	r.printFindings(r.Confirmed, "confirmed", utils.Green)
	r.printFindings(r.Candidates, "candidates", utils.Yellow)
	fmt.Printf("targets: %d | params tested: %d | reflections: %d | confirmed: %s | candidates: %s\n",
		len(r.Targets), r.Parameters, r.Reflections,
		utils.C(utils.Green, fmt.Sprint(len(r.Confirmed))),
		utils.C(utils.Yellow, fmt.Sprint(len(r.Candidates))))
	if len(r.WAF) > 0 {
		fmt.Printf("waf detected: %s\n", utils.C(utils.Red, strings.Join(r.WAF, ", ")))
	}
	fmt.Println(utils.C(utils.Gray, line))
}

func (r *Report) printFindings(list []*models.Finding, label, color string) {
	seen := map[string][]*models.Finding{}
	for _, f := range list {
		key := f.Vector + "|" + f.Confirmation
		seen[key] = append(seen[key], f)
	}
	if len(seen) == 0 {
		return
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		items := seen[k]
		fmt.Printf(" %s %s (%d):\n", utils.C(color, "["+label+"]"), k, len(items))
		for _, f := range items {
			fmt.Printf("   - %s %s  param:%s  payload:%q\n", f.Method, f.URL, f.Parameter, f.Payload)
		}
	}
}

// resolvePath mirrors the source tool's behavior: bare filenames land in
// output/, paths containing a separator are honored verbatim.
func resolvePath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("empty path")
	}
	if strings.ContainsRune(path, filepath.Separator) || strings.HasPrefix(path, "/") {
		if dir := filepath.Dir(path); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return "", err
			}
		}
		return path, nil
	}
	if err := os.MkdirAll("output", 0o755); err != nil {
		return "", err
	}
	return filepath.Join("output", path), nil
}

// WriteJSON serializes the report to disk and returns the file path.
func (r *Report) WriteJSON(path string) (string, error) {
	final, err := resolvePath(path)
	if err != nil {
		return "", err
	}
	r.GeneratedAt = time.Now()
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(final, append(raw, '\n'), 0o644); err != nil {
		return "", err
	}
	return final, nil
}

var htmlTemplateHTML = `<!doctype html>
<html><head><meta charset="utf-8"><title>xsshunts report</title>
<style>
body{font-family:ui-monospace,Menlo,Consolas,monospace;background:#0e1116;color:#d7dae1;margin:24px}
h1{color:#7cf1ff}h1 small{color:#565f6e;font-weight:400}
table{border-collapse:collapse;width:100%;margin:14px 0}
th,td{border:1px solid #2a313c;padding:6px 10px;font-size:13px;text-align:left;vertical-align:top}
th{background:#161b22;color:#9fb6c9}
tr.confirmed td{background:rgba(46,160,67,.14)}
tr.candidate td{background:rgba(229,171,41,.10)}
.tag{padding:1px 7px;border-radius:10px;font-size:12px}
.tag.c{background:#1f883d;color:#fff}.tag.r{background:#bb8009;color:#fff}
code{background:#161b22;padding:1px 4px;border-radius:4px}
.footer{color:#565f6e;margin-top:22px;font-size:12px}
</style></head><body>
<h1>xsshunts <small>v{{.Version}}</small></h1>
<p>generated {{.GeneratedAt}} &middot; targets: <b>{{.Targets}}</b> &middot; params: <b>{{.Params}}</b> &middot; reflections: <b>{{.Reflections}}</b> &middot; confirmed: <b>{{.Confirmed}}</b> &middot; candidates: <b>{{.Candidates}}</b>{{if .WAF}} &middot; waf: <b>{{.WAF}}</b>{{end}}</p>
<table><tr><th>#</th><th>level</th><th>vector</th><th>method</th><th>url</th><th>param</th><th>payload</th><th>context</th><th>evidence</th></tr>
{{range $n, $f := .Rows}}<tr class="{{$f.Class}}"><td>{{$n}}</td><td><span class="tag {{$f.Class}}">{{$f.Level}}</span></td><td>{{$f.Vector}}</td><td>{{$f.Method}}</td><td><code>{{$f.URL}}</code></td><td>{{$f.Param}}</td><td><code>{{$f.Payload}}</code></td><td>{{$f.Context}}</td><td>{{$f.Evidence}}</td></tr>{{end}}
{{if eq (len .Rows) 0}}<tr><td colspan="9">no findings recorded</td></tr>{{end}}
</table>
<p class="footer">Only use this tool on systems you are authorized to test. Verified findings triggered a monitored JavaScript dialog in a controlled browser session.</p>
</body></html>`

type htmlRow struct {
	Class, Level, Vector, Method, URL, Param, Payload, Context, Evidence string
}

// WriteHTML renders the human-friendly HTML report.
func (r *Report) WriteHTML(path string) (string, error) {
	final, err := resolvePath(path)
	if err != nil {
		return "", err
	}
	rows := []htmlRow{}
	for _, f := range r.Confirmed {
		rows = append(rows, htmlRow{Class: "confirmed", Level: "confirmed", Vector: f.Vector, Method: f.Method, URL: f.URL, Param: f.Parameter, Payload: f.Payload, Context: f.Context, Evidence: f.Evidence})
	}
	for _, f := range r.Candidates {
		rows = append(rows, htmlRow{Class: "candidate", Level: "candidate", Vector: f.Vector, Method: f.Method, URL: f.URL, Param: f.Parameter, Payload: f.Payload, Context: f.Context, Evidence: f.Evidence})
	}
	data := struct {
		Version, GeneratedAt, Targets, Params, Reflections, Confirmed, Candidates, WAF string
		Rows                                                                          []htmlRow
	}{
		Version:     config.Version,
		GeneratedAt: time.Now().Format(time.RFC1123),
		Targets:     fmt.Sprint(len(r.Targets)),
		Params:      fmt.Sprint(r.Parameters),
		Reflections: fmt.Sprint(r.Reflections),
		Confirmed:   fmt.Sprint(len(r.Confirmed)),
		Candidates:  fmt.Sprint(len(r.Candidates)),
		Rows:        rows,
	}
	if len(r.WAF) > 0 {
		data.WAF = strings.Join(r.WAF, ", ")
	}
	var out strings.Builder
	tpl, err := template.New("xsshunts").Parse(htmlTemplateHTML)
	if err != nil {
		return "", err
	}
	if err := tpl.Execute(&out, data); err != nil {
		return "", err
	}
	if err := os.WriteFile(final, []byte(out.String()), 0o644); err != nil {
		return "", err
	}
	return final, nil
}
