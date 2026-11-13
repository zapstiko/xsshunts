// Package rawrequest parses raw HTTP requests exported from tools such as
// Burp Suite (Proxy → Copy request / Save item) so they can be scanned
// directly with their headers, cookies and form fields.
package rawrequest

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/zapstiko/xsshunts/models"
)

// Request is a parsed raw HTTP request ready for scanning.
type Request struct {
	Method      string
	URL         string
	Headers     map[string]string
	Postfields  map[string]string
	Cookies     []models.CookieEntry
	UserAgent   string
	ContentType string

	// UnsupportedBody explains why a request body was not fuzzed (e.g. JSON).
	UnsupportedBody string
}

// hop-by-hop and browser-managed headers are not forwarded.
var skippedHeaders = map[string]bool{
	"host":              true,
	"content-length":    true,
	"connection":        true,
	"proxy-connection":  true,
	"transfer-encoding": true,
	"upgrade":           true,
	"accept-encoding":   true,
	"expect":            true,
}

// Parse parses one raw HTTP request. schemeOverride may be "http", "https" or
// empty to infer the scheme from the Host header.
func Parse(data []byte, schemeOverride string) (*Request, error) {
	text := strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\r", "\n")
	text = strings.TrimLeft(text, "\n")
	if strings.TrimSpace(text) == "" {
		return nil, errors.New("empty raw request")
	}

	head, body, _ := strings.Cut(text, "\n\n")
	lines := strings.Split(head, "\n")
	if len(lines) == 0 {
		return nil, errors.New("raw request has no request line")
	}

	fields := strings.Fields(strings.TrimSpace(lines[0]))
	if len(fields) < 2 {
		return nil, fmt.Errorf("invalid request line: %q", strings.TrimSpace(lines[0]))
	}
	method := strings.ToUpper(fields[0])
	if method != "GET" && method != "POST" {
		return nil, fmt.Errorf("unsupported method %s (Burp request import supports GET and POST)", method)
	}
	target := fields[1]

	headers, err := parseHeaders(lines[1:])
	if err != nil {
		return nil, err
	}

	host := headerValue(headers, "Host")
	scheme := strings.ToLower(strings.TrimSpace(schemeOverride))
	if scheme != "" && scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme %q (use http or https)", scheme)
	}

	var fullURL string
	switch {
	case strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://"):
		fullURL = target
	case strings.HasPrefix(target, "//"):
		if scheme == "" {
			scheme = "https"
		}
		fullURL = scheme + ":" + target
	default:
		if host == "" {
			return nil, errors.New("request has no Host header and no absolute URL")
		}
		if scheme == "" {
			scheme = inferScheme(host)
		}
		path := target
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		fullURL = scheme + "://" + host + path
	}

	parsed, err := url.Parse(fullURL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, fmt.Errorf("invalid request URL %q", fullURL)
	}

	req := &Request{
		Method:      method,
		URL:         fullURL,
		Headers:     map[string]string{},
		Postfields:  map[string]string{},
		ContentType: headerValue(headers, "Content-Type"),
	}

	req.UserAgent = headerValue(headers, "User-Agent")
	if cookieHeader := headerValue(headers, "Cookie"); cookieHeader != "" {
		for _, part := range strings.Split(cookieHeader, ";") {
			part = strings.TrimSpace(part)
			name, value, ok := strings.Cut(part, "=")
			if !ok || strings.TrimSpace(name) == "" {
				continue
			}
			req.Cookies = append(req.Cookies, models.CookieEntry{
				Name:  strings.TrimSpace(name),
				Value: strings.TrimSpace(value),
				URL:   fullURL,
			})
		}
	}

	for key, value := range headers {
		lower := strings.ToLower(key)
		if skippedHeaders[lower] || lower == "cookie" || lower == "user-agent" || lower == "content-type" {
			continue
		}
		req.Headers[key] = value
	}

	if method == "POST" && strings.TrimSpace(body) != "" {
		switch {
		case isFormURLEncoded(req.ContentType) || (req.ContentType == "" && looksFormURLEncoded(body)):
			values, err := url.ParseQuery(body)
			if err != nil {
				return nil, fmt.Errorf("invalid urlencoded body: %w", err)
			}
			for key, vals := range values {
				if len(vals) > 0 {
					req.Postfields[key] = vals[len(vals)-1]
				}
			}
		default:
			req.UnsupportedBody = "request body is not application/x-www-form-urlencoded; only URL, cookie and header vectors will be tested"
		}
	}

	return req, nil
}

func parseHeaders(lines []string) (map[string]string, error) {
	headers := map[string]string{}
	lastKey := ""
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) && lastKey != "" {
			headers[lastKey] += " " + strings.TrimSpace(line)
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" {
			continue
		}
		if previous, exists := headers[key]; exists {
			separator := ", "
			if strings.EqualFold(key, "Cookie") {
				separator = "; "
			}
			headers[key] = previous + separator + value
			continue
		}
		headers[key] = value
		lastKey = key
	}
	return headers, nil
}

func headerValue(headers map[string]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}

func isFormURLEncoded(contentType string) bool {
	contentType = strings.ToLower(contentType)
	return strings.Contains(contentType, "application/x-www-form-urlencoded")
}

func looksFormURLEncoded(body string) bool {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" || strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") || strings.HasPrefix(trimmed, "<") {
		return false
	}
	if !strings.Contains(trimmed, "=") {
		return false
	}
	values, err := url.ParseQuery(trimmed)
	return err == nil && len(values) > 0
}

func inferScheme(host string) string {
	lower := strings.ToLower(strings.TrimSpace(host))
	if strings.HasSuffix(lower, ":80") {
		return "http"
	}
	if strings.HasSuffix(lower, ":443") {
		return "https"
	}
	hostname := lower
	if i := strings.LastIndex(lower, ":"); i > 0 && !strings.Contains(lower[i:], "]") {
		hostname = lower[:i]
	}
	hostname = strings.Trim(hostname, "[]")
	if hostname == "localhost" || hostname == "::1" ||
		strings.HasPrefix(hostname, "127.") || strings.HasPrefix(hostname, "192.168.") ||
		strings.HasPrefix(hostname, "10.") {
		return "http"
	}
	return "https"
}
