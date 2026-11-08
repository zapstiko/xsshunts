// Package utils contains shared helpers used across all xsshunts packages.
package utils

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"net/url"
	"regexp"
	"strings"
	"time"

	xhtml "golang.org/x/net/html"

	"github.com/zapstiko/xsshunts/config"
	"github.com/zapstiko/xsshunts/models"
)

var rnd = rand.New(rand.NewSource(time.Now().UnixNano()))

// RandomString produces a random alphanumeric string.
func RandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rnd.Intn(len(charset))]
	}
	return string(b)
}

// RandUniform returns a uniform float in [min, max).
func RandUniform(min float64, max float64) float64 {
	if max <= min {
		return min
	}
	return min + rnd.Float64()*(max-min)
}

// RandInt returns a uniform int in [min, max] inclusive.
func RandInt(min, max int) int {
	if max <= min {
		return min
	}
	return min + rnd.Intn(max-min+1)
}

// ShuffleStrings returns a random permutation of items.
func ShuffleStrings(items []string) []string {
	out := append([]string(nil), items...)
	rnd.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

// DelayMs sleeps a random duration between minMs and maxMs.
func DelayMs(minMs, maxMs int) {
	var delay float64
	if maxMs <= minMs {
		delay = float64(minMs)
	} else {
		delay = RandUniform(float64(minMs), float64(maxMs))
	}
	time.Sleep(time.Duration(delay) * time.Millisecond)
}

// IsValidURL reports whether a string parses as a http(s) URL with a host.
func IsValidURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// MainDomain returns the host (+port) part of a URL.
func MainDomain(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

// IsSameOrigin reports whether two URLs share scheme and host.
func IsSameOrigin(url1, url2 string) bool {
	p1, err1 := url.Parse(url1)
	p2, err2 := url.Parse(url2)
	if err1 != nil || err2 != nil {
		return false
	}
	return p1.Scheme == p2.Scheme && p1.Host == p2.Host
}

// CleanErrorText trims an error message to a single 120-char line.
func CleanErrorText(errText string) string {
	if errText == "" {
		return "Unknown error"
	}
	firstLine := strings.SplitN(strings.TrimSpace(errText), "\n", 2)[0]
	collapse := strings.Join(strings.Fields(firstLine), " ")
	if len(collapse) > 120 {
		collapse = collapse[:120]
	}
	return collapse
}

// CurrentTime returns the XSSRush-style timestamp.
func CurrentTime() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

// IsExcludedParam checks the exact list then the substring markers.
func IsExcludedParam(name string, excludedVars []string, excludedVarsRegex []string) bool {
	if name == "" {
		return true
	}
	lower := strings.ToLower(name)
	for _, item := range excludedVars {
		if strings.ToLower(item) == lower {
			return true
		}
	}
	for _, pattern := range excludedVarsRegex {
		if strings.Contains(lower, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// KV is one ordered query parameter pair.
type KV struct {
	Key   string
	Value string
}

// PatchKeyValue replaces every occurrence of a key with a single value.
func PatchKeyValue(pairs []KV, key, value string) []KV {
	out := make([]KV, 0, len(pairs))
	found := false
	for _, kv := range pairs {
		if kv.Key == key {
			if !found {
				out = append(out, KV{Key: key, Value: value})
				found = true
			}
			continue
		}
		out = append(out, kv)
	}
	if !found {
		out = append(out, KV{Key: key, Value: value})
	}
	return out
}

// ParseQueryOrdered keeps every k=v pair (including duplicates) in source order.
func ParseQueryOrdered(rawQuery string) []KV {
	var out []KV
	if rawQuery == "" {
		return out
	}
	for _, pair := range strings.Split(rawQuery, "&") {
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		ku, err1 := url.QueryUnescape(k)
		vu, err2 := url.QueryUnescape(v)
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, KV{Key: ku, Value: vu})
	}
	return out
}

// BuildQueryOrdered renders ordered pairs like Python's urlencode.
func BuildQueryOrdered(pairs []KV) string {
	var parts []string
	for _, kv := range pairs {
		parts = append(parts, url.QueryEscape(kv.Key)+"="+url.QueryEscape(kv.Value))
	}
	return strings.Join(parts, "&")
}

// Base64EncodeString encodes a string as standard base64.
func Base64EncodeString(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// Round rounds a float to the given decimal places.
func Round(v float64, places int) float64 {
	shift := 1.0
	for i := 0; i < places; i++ {
		shift *= 10
	}
	return float64(int(v*shift+0.5)) / shift
}

// BuildGetURL merges named params onto a base URL (replacing existing keys in place).
func BuildGetURL(baseURL string, paramNames []string, paramValues []string) string {
	u, err := url.Parse(baseURL)
	if err != nil {
		return baseURL
	}
	pairs := ParseQueryOrdered(u.RawQuery)
	seen := map[string]bool{}
	for i, name := range paramNames {
		if seen[name] || i >= len(paramValues) {
			continue
		}
		seen[name] = true
		pairs = PatchKeyValue(pairs, name, paramValues[i])
	}
	u.RawQuery = BuildQueryOrdered(pairs)
	return u.String()
}

// PercentEncode encodes a payload like Python's quote(payload, safe="").
func PercentEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// BuildPayloadedURL injects a payload into one query parameter of a URL.
func BuildPayloadedURL(endpoint, paramName, payload string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		return endpoint
	}
	pairs := ParseQueryOrdered(u.RawQuery)
	pairs = PatchKeyValue(pairs, paramName, payload)
	u.RawQuery = BuildQueryOrdered(pairs)
	return u.String()
}

// BuildPayloadedBody builds a urlencoded POST body where only one param carries the payload.
func BuildPayloadedBody(params []*models.Parameter, targetParamName, payload string) string {
	var pairs []KV
	found := false
	for _, p := range params {
		name := p.ParamName
		val := p.ParamValue
		if name == targetParamName {
			pairs = append(pairs, KV{Key: name, Value: payload})
			found = true
		} else {
			pairs = append(pairs, KV{Key: name, Value: val})
		}
	}
	if !found {
		pairs = append(pairs, KV{Key: targetParamName, Value: payload})
	}
	return BuildQueryOrdered(pairs)
}

// BuildPathPayloadURL replaces the path marker with the encoded payload.
func BuildPathPayloadURL(testPath, payload string) string {
	return strings.Replace(testPath, "[PATH_BASED_TESTING]", PercentEncode(payload), 1)
}

// BuildFragmentPayloadURL appends a raw payload as URL fragment.
func BuildFragmentPayloadURL(target, payload string) string {
	base := strings.SplitN(target, "#", 2)[0]
	return base + "#" + payload
}

// GeneratePostBasedPOC returns the base64 data-URL HTML reproduction page.
func GeneratePostBasedPOC(action string, formData map[string]string, order []string) string {
	var hiddenInputs []string
	for _, k := range order {
		v, _ := formData[k]
		safeVal := xhtml.EscapeString(v)
		safeKey := xhtml.EscapeString(k)
		hiddenInputs = append(hiddenInputs,
			fmt.Sprintf(`<input type="hidden" name="%s" value="%s">`, safeKey, safeVal))
	}
	inputsHTML := strings.Join(hiddenInputs, "\n")

	formBlock := fmt.Sprintf(`<form method="post" action="%s">
%s
<button>XSS</button>
</form>`, action, inputsHTML)
	optOutPOC := xhtml.EscapeString(formBlock)
	finalPOC := "<h1>XSS by XSSHuntS!</h1>\n" + formBlock + "\n<br><pre>" + optOutPOC + "</pre>"
	return "data:text/html;base64," + Base64EncodeString(finalPOC)
}

// BuildRawHTTPRequest reproduces the raw HTTP request block stored in the JSON report.
func BuildRawHTTPRequest(finding *models.XSSFinding, userAgent string) string {
	if userAgent == "" {
		userAgent = config.DefaultUserAgent
	}
	rawURL := finding.RequestURL
	if rawURL == "" {
		rawURL = finding.Endpoint
	}
	if rawURL == "" {
		rawURL = "/"
	}
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "http://" + rawURL
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	path := parsed.Path
	if path == "" {
		path = "/"
	}
	if parsed.RawQuery != "" {
		path += "?" + parsed.RawQuery
	}
	if parsed.Fragment != "" {
		path += "#" + parsed.Fragment
	}
	host := parsed.Host
	if host == "" {
		host = "localhost"
	}
	method := strings.ToUpper(finding.RequestMethod)
	if method == "HEADER" {
		hName := strings.TrimSpace(strings.TrimPrefix(finding.ParamName, "Header: "))
		switch strings.ToLower(hName) {
		case "host":
			return strings.Join([]string{
				fmt.Sprintf("GET %s", path),
				fmt.Sprintf("Host: %s", finding.PayloadValue),
				fmt.Sprintf("User-Agent: %s", userAgent),
			}, "\n")
		case "user-agent", "useragent":
			return strings.Join([]string{
				fmt.Sprintf("GET %s", path),
				fmt.Sprintf("Host: %s", host),
				fmt.Sprintf("User-Agent: %s", finding.PayloadValue),
			}, "\n")
		default:
			return strings.Join([]string{
				fmt.Sprintf("GET %s", path),
				fmt.Sprintf("Host: %s", host),
				fmt.Sprintf("User-Agent: %s", userAgent),
				fmt.Sprintf("%s: %s", hName, finding.PayloadValue),
			}, "\n")
		}
	}
	if method == "POST" {
		return strings.Join([]string{
			fmt.Sprintf("POST %s", path),
			fmt.Sprintf("Host: %s", host),
			fmt.Sprintf("User-Agent: %s", userAgent),
			"",
			finding.RequestBody,
		}, "\n")
	}
	return strings.Join([]string{
		fmt.Sprintf("GET %s", path),
		fmt.Sprintf("Host: %s", host),
		fmt.Sprintf("User-Agent: %s", userAgent),
	}, "\n")
}

// unused import guard for regexp (kept for helpers that may use it)
var _ = regexp.MustCompile
