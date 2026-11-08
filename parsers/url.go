// Package parsers implements URL-oriented helpers of the scanner.
package parsers

import (
	"net/url"
	"strings"
)

// ResolveActionURL resolves a form's action against the base URL of the page.
func ResolveActionURL(action, baseURL string) string {
	if strings.TrimSpace(action) == "" {
		return baseURL
	}
	action = strings.TrimSpace(action)
	parsedBase, err := url.Parse(baseURL)
	if err != nil {
		return baseURL
	}
	origin := parsedBase.Scheme + "://" + parsedBase.Host

	switch {
	case strings.HasPrefix(action, "//"):
		return parsedBase.Scheme + ":" + action
	case strings.HasPrefix(action, "/"):
		return origin + action
	case strings.HasPrefix(action, "http://"), strings.HasPrefix(action, "https://"):
		return action
	default:
		separator := ""
		if !strings.HasSuffix(origin, "/") && !strings.HasPrefix(action, "/") {
			separator = "/"
		}
		return origin + separator + action
	}
}

// ParsePostfieldsString turns 'k=v&k2=v2' into a map.
func ParsePostfieldsString(raw string) map[string]string {
	result := map[string]string{}
	if strings.TrimSpace(raw) == "" {
		return result
	}
	for _, pair := range strings.Split(raw, "&") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		key, value, hasEq := strings.Cut(pair, "=")
		if !hasEq {
			value = ""
		}
		key = unquote(key)
		value = unquote(value)
		if key != "" {
			result[key] = value
		}
	}
	return result
}

func unquote(s string) string {
	unescaped, err := url.QueryUnescape(strings.TrimSpace(s))
	if err != nil {
		return strings.TrimSpace(s)
	}
	return unescaped
}

// BuildTestPaths produces the path-injection candidate URLs.
func BuildTestPaths(targetURL string) []string {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return nil
	}
	baseURL := parsed.Scheme + "://" + parsed.Host
	rawPath := strings.Trim(parsed.Path, "/")
	var segments []string
	if rawPath != "" {
		segments = strings.Split(rawPath, "/")
	}

	if len(segments) == 0 {
		return []string{baseURL + "/[PATH_BASED_TESTING]"}
	}

	testPaths := []string{baseURL + "/" + strings.Join(segments, "/") + "/[PATH_BASED_TESTING]"}

	testSegs := append([]string(nil), segments...)
	testSegs[len(testSegs)-1] = "[PATH_BASED_TESTING]"
	testPaths = append(testPaths, baseURL+"/"+strings.Join(testSegs, "/"))

	for i := len(segments) - 2; i >= 0; i-- {
		testSegs := append([]string(nil), segments...)
		testSegs[i] = "[PATH_BASED_TESTING]"
		testPaths = append(testPaths, baseURL+"/"+strings.Join(testSegs, "/"))
	}
	return testPaths
}

// ExtractQueryDict returns the query parameters of a URL as a map.
func ExtractQueryDict(targetURL string) map[string]string {
	out := map[string]string{}
	u, err := url.Parse(targetURL)
	if err != nil {
		return out
	}
	for key, values := range u.Query() {
		if len(values) > 0 {
			out[key] = values[0]
		} else {
			out[key] = ""
		}
	}
	return out
}
