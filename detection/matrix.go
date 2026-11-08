package detection

import (
	"fmt"
	"strings"
)

// ProbeChars is the special-character reflection matrix set (order matters).
var ProbeChars = []string{"'", "\"", "<", ">", "/", ";", "(", ")", "{", "}", "=", "`"}

// EscapeMap lists known escaping transformations per character.
var EscapeMap = map[string][]string{
	"<":  {"&lt;", "&#60;", "&#x3c;", `\u003c`, `\x3c`, "%3c"},
	">":  {"&gt;", "&#62;", "&#x3e;", `\u003e`, `\x3e`, "%3e"},
	"\"": {"&quot;", "&#34;", "&#x22;", `\"`, `\u0022`, `\x22`, "%22"},
	"'":  {"&#39;", "&apos;", "&#x27;", `\'`, `\u0027`, `\x27`, "%27"},
	"/":  {"&#47;", "&#x2f;", `\/`, "%2f"},
	";":  {"&#59;", "&#x3b;", "%3b"},
	"(":  {"&#40;", "&#x28;", "%28"},
	")":  {"&#41;", "&#x29;", "%29"},
	"{":  {"&#123;", "&#x7b;", "%7b"},
	"}":  {"&#125;", "&#x7d;", "%7d"},
	"=":  {"&#61;", "&#x3d;", "%3d"},
	"`":  {"&#96;", "&#x60;", "\\`", "%60"},
}

// BuildMatrixProbe encodes all probe chars together with their index markers.
func BuildMatrixProbe(token string) string {
	var b strings.Builder
	for idx, ch := range ProbeChars {
		fmt.Fprintf(&b, "%s%d%s%s", token, idx, ch, token)
	}
	return b.String()
}

// AnalyzeCharacterMatrix classifies each probe character reflection.
func AnalyzeCharacterMatrix(html string, token string) map[string]string {
	results := map[string]string{}
	lowerHTML := strings.ToLower(html)
	for idx, ch := range ProbeChars {
		rawPattern := fmt.Sprintf("%s%d%s%s", token, idx, ch, token)
		strippedPattern := fmt.Sprintf("%s%d%s", token, idx, token)
		switch {
		case strings.Contains(html, rawPattern):
			results[ch] = "allowed"
		case containsAnyEscape(lowerHTML, fmt.Sprintf("%s%d", token, idx), token, ch):
			results[ch] = "escaped"
		case strings.Contains(html, strippedPattern):
			results[ch] = "filtered"
		case strings.Contains(html, fmt.Sprintf("%s%d", token, idx)):
			results[ch] = "replaced"
		default:
			results[ch] = "absent"
		}
	}
	return results
}

func containsAnyEscape(lowerHTML, before, after, ch string) bool {
	wrapped := func(esc string) string { return strings.ToLower(before + esc + after) }
	for _, esc := range EscapeMap[ch] {
		if strings.Contains(lowerHTML, wrapped(esc)) {
			return true
		}
	}
	return false
}

// FormatMatrixSummary buckets a matrix into allowed/escaped/filtered/replaced lists.
func FormatMatrixSummary(matrix map[string]string) map[string][]string {
	summary := map[string][]string{"allowed": {}, "escaped": {}, "filtered": {}, "replaced": {}}
	for ch, status := range matrix {
		if _, ok := summary[status]; ok {
			summary[status] = append(summary[status], ch)
		}
	}
	return summary
}
