// Package reporter renders console summaries and exports JSON reports.
package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/zapstiko/xsshunts/appmeta"
	"github.com/zapstiko/xsshunts/config"
	"github.com/zapstiko/xsshunts/detection"
	"github.com/zapstiko/xsshunts/logger"
	"github.com/zapstiko/xsshunts/models"
	"github.com/zapstiko/xsshunts/utils"
)

// ANSI aliases for report rendering.
const (
	reset  = logger.Reset
	bold   = logger.Bold
	dim    = logger.Dim
	red    = logger.Red
	green  = logger.Green
	yellow = logger.Yellow
	cyan   = logger.Cyan
	white  = logger.White
)

// Reporter collects scan results and renders/exports them.
type Reporter struct {
	Findings   []*models.XSSFinding
	Parameters []*models.Parameter
	Logger     *logger.Logger
	UserAgent  string
	MiningOnly bool
	Silent     bool
}

// New creates a reporter.
func New(findings []*models.XSSFinding, parameters []*models.Parameter, log *logger.Logger, miningOnly, silent bool) *Reporter {
	return &Reporter{
		Findings:   findings,
		Parameters: parameters,
		Logger:     log,
		UserAgent:  config.DefaultUserAgent,
		MiningOnly: miningOnly,
		Silent:     silent,
	}
}

func matrixParts(matrix map[string]string) string {
	var allowed, escaped, filtered []string
	for _, ch := range detection.ProbeChars {
		status, ok := matrix[ch]
		if !ok {
			continue
		}
		switch status {
		case "allowed":
			allowed = append(allowed, ch)
		case "escaped":
			escaped = append(escaped, ch)
		case "filtered":
			filtered = append(filtered, ch)
		}
	}
	var parts []string
	if len(allowed) > 0 {
		parts = append(parts, fmt.Sprintf("%sallowed: [ %s ]%s", green, strings.Join(allowed, " "), reset))
	}
	if len(escaped) > 0 {
		parts = append(parts, fmt.Sprintf("%sescaped: [ %s ]%s", yellow, strings.Join(escaped, " "), reset))
	}
	if len(filtered) > 0 {
		parts = append(parts, fmt.Sprintf("%sfiltered: [ %s ]%s", red, strings.Join(filtered, " "), reset))
	}
	return strings.Join(parts, " | ")
}

// PrintMiningSummary renders the parameter mining summary.
func (r *Reporter) PrintMiningSummary() {
	if r.Silent {
		return
	}

	type reflectedItem struct {
		param *models.Parameter
		refs  []*models.ReflectionResult
	}
	var reflected []reflectedItem
	for _, p := range r.Parameters {
		var active []*models.ReflectionResult
		for _, ref := range p.Reflections {
			if ref.Reflected {
				active = append(active, ref)
			}
		}
		if len(active) > 0 {
			reflected = append(reflected, reflectedItem{param: p, refs: active})
		}
	}

	fmt.Printf("\n%s[*] parameter mining summary:%s\n", bold, reset)
	fmt.Printf("  total parameters discovered : %s%d%s\n", bold, len(r.Parameters), reset)
	if len(reflected) > 0 {
		fmt.Printf("  reflected parameters        : %s%s%d%s\n", bold, green, len(reflected), reset)
	} else {
		fmt.Printf("  reflected parameters        : %s%d%s\n", bold, len(reflected), reset)
	}

	if len(reflected) == 0 {
		fmt.Printf("\n[%s%s!%s] no reflected parameters found.\n\n", bold, yellow, reset)
		return
	}

	fmt.Printf("\n%s%s[+] REFLECTED PARAMETERS:%s\n", bold, green, reset)
	for idx, item := range reflected {
		p := item.param
		fmt.Printf("  (%d) %s%s%s%s [%s]\n", idx+1, bold, white, p.ParamName, reset, p.Location)
		fmt.Printf("      endpoint   : %s\n", p.ActionURL)
		var ctxStrs []string
		for _, ref := range item.refs {
			tagStr := ""
			if ref.Tags != "" {
				tagStr = fmt.Sprintf(" (tag: <%s>)", ref.Tags)
			}
			ctxStrs = append(ctxStrs, strings.ToUpper(ref.Context)+tagStr)
		}
		fmt.Printf("      context    : %s\n", strings.Join(ctxStrs, ", "))
		if len(p.CharMatrix) > 0 {
			if parts := matrixParts(p.CharMatrix); parts != "" {
				fmt.Printf("      characters : %s\n", parts)
			}
		}
	}
	fmt.Println()
}

func (r *Reporter) printFindingItem(idx int, f *models.XSSFinding) {
	paramStr := f.ParamName
	if paramStr == "" {
		paramStr = "[Path/Hash]"
	}
	fmt.Printf("  (%d) %s%s%s%s [%s]\n", idx, bold, white, paramStr, reset, f.RequestMethod)
	targetURL := f.RequestURL
	if targetURL == "" {
		targetURL = f.Endpoint
	}
	fmt.Printf("      url        : %s\n", targetURL)
	if strings.ToUpper(f.RequestMethod) == "POST" && f.RequestBody != "" {
		fmt.Printf("      postfields : %s\n", f.RequestBody)
	}
	fmt.Printf("      context    : %s\n", f.Context)
	fmt.Printf("      payload    : %s%s%s\n", bold, white, f.PayloadValue)
	fmt.Printf("      confidence : %s\n", logger.FormatConfidence(f.Confidence))
	if f.ProofOfConcept != "" {
		fmt.Printf("      poc        : %s%s%s\n", cyan, f.ProofOfConcept, reset)
	}
}

// PrintSummary renders the final scan summary.
func (r *Reporter) PrintSummary() {
	if r.Silent {
		return
	}
	if r.MiningOnly {
		r.PrintMiningSummary()
		return
	}

	var verified, matches []*models.XSSFinding
	for _, f := range r.Findings {
		if f.XSS == 1 {
			verified = append(verified, f)
		} else if f.XSMatch == 1 {
			matches = append(matches, f)
		}
	}

	fmt.Printf("\n%s[*] scan report summary:%s\n", bold, reset)
	fmt.Printf("  total parameters audited : %s%d%s\n", bold, len(r.Parameters), reset)
	verifiedColor := green
	if len(verified) > 0 {
		verifiedColor = red
	}
	fmt.Printf("  verified vulnerabilities : %s%d%s\n", bold+verifiedColor, len(verified), reset)
	matchesColor := ""
	if len(matches) > 0 {
		matchesColor = yellow
	}
	fmt.Printf("  reflection matches       : %s%d%s\n", bold+matchesColor, len(matches), reset)

	if len(r.Findings) == 0 {
		fmt.Printf("\n[%s%s+%s] all tested parameters appear to be safe from XSS.\n\n", bold, green, reset)
		return
	}

	if len(verified) > 0 {
		fmt.Printf("\n%s%s[!] VERIFIED CROSS-SITE SCRIPTING (XSS) VULNERABILITIES:%s\n", bold, red, reset)
		for idx, f := range verified {
			r.printFindingItem(idx+1, f)
		}
	}
	if len(matches) > 0 {
		fmt.Printf("\n%s%s[*] UNESCAPED REFLECTION MATCHES (POTENTIAL SINKS):%s\n", bold, yellow, reset)
		for idx, f := range matches {
			r.printFindingItem(idx+1, f)
		}
	}
	fmt.Println()
}

// RenderConsole prints the appropriate console report.
func (r *Reporter) RenderConsole() {
	if r.Silent {
		return
	}
	if r.MiningOnly {
		r.PrintMiningSummary()
	} else {
		r.PrintSummary()
	}
}

// ExportJSON writes the scan report as JSON.
func (r *Reporter) ExportJSON(filepath string) error {
	if dir := filepathDir(filepath); dir != "" {
		_ = os.MkdirAll(dir, 0o755)
	}

	if r.MiningOnly {
		var reflectedData []map[string]interface{}
		for _, p := range r.Parameters {
			var active []*models.ReflectionResult
			for _, ref := range p.Reflections {
				if ref.Reflected {
					active = append(active, ref)
				}
			}
			if len(active) == 0 {
				continue
			}
			var contexts []map[string]interface{}
			for _, ref := range active {
				ctxItem := map[string]interface{}{
					"context": ref.Context,
					"method":  ref.RequestMethod,
				}
				if ref.Tags != "" {
					ctxItem["tag"] = ref.Tags
				}
				contexts = append(contexts, ctxItem)
			}
			refItem := map[string]interface{}{
				"parameter": p.ParamName,
				"location":  p.Location,
				"endpoint":  p.ActionURL,
				"contexts":  contexts,
			}
			if len(p.CharMatrix) > 0 {
				refItem["char_matrix"] = p.CharMatrix
			}
			reflectedData = append(reflectedData, refItem)
		}

		report := map[string]interface{}{
			"scanner":                     "XSSHuntS (xsshunts)",
			"version":                     appmeta.Version,
			"github":                      appmeta.GitHub,
			"mode":                        "parameter_mining",
			"total_parameters_discovered": len(r.Parameters),
			"total_reflected_parameters":  len(reflectedData),
			"reflected_parameters":        reflectedData,
		}
		return writeJSON(filepath, report)
	}

	var findingsData []map[string]interface{}
	for _, f := range r.Findings {
		item := map[string]interface{}{
			"finding_uuid":  f.FindingUUID,
			"endpoint":      f.Endpoint,
			"parameter":     f.ParamName,
			"location":      f.RequestMethod,
			"context":       f.Context,
			"payload_name":  f.PayloadName,
			"payload_key":   f.PayloadKey,
			"payload_value": f.PayloadValue,
			"xss":           f.XSS,
			"confidence":    f.Confidence,
			"request_url":   f.RequestURL,
		}
		if strings.ToUpper(f.RequestMethod) == "POST" {
			item["postfields"] = f.RequestBody
		}
		item["http"] = utils.BuildRawHTTPRequest(f, r.UserAgent)
		item["proof_of_concept"] = f.ProofOfConcept
		item["created_at"] = f.CreatedAt
		findingsData = append(findingsData, item)
	}

	var paramData []map[string]interface{}
	for _, p := range r.Parameters {
		item := map[string]interface{}{
			"parameter": p.ParamName,
			"location":  p.Location,
			"endpoint":  p.ActionURL,
		}
		if len(p.CharMatrix) > 0 {
			item["char_matrix"] = p.CharMatrix
		}
		paramData = append(paramData, item)
	}

	totalXSS := 0
	for _, f := range r.Findings {
		if f.XSS == 1 {
			totalXSS++
		}
	}

	report := map[string]interface{}{
		"scanner":          "XSSHuntS (xsshunts)",
		"version":          appmeta.Version,
		"github":           appmeta.GitHub,
		"total_parameters": len(r.Parameters),
		"total_findings":   len(r.Findings),
		"total_xss":        totalXSS,
		"parameters":       paramData,
		"findings":         findingsData,
	}
	return writeJSON(filepath, report)
}

func writeJSON(path string, report interface{}) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func filepathDir(path string) string {
	return filepath.Dir(path)
}
