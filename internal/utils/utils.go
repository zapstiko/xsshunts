// Package utils provides shared helpers: colored printing, tokens, delays and
// the audit HTTP client (cookies, custom headers, WAF + rate-limit handling).
package utils

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/zapstiko/xsshunts/internal/config"
	"github.com/zapstiko/xsshunts/internal/detection"
)

// ANSI colors.
const (
	Reset  = "\033[0m"
	Bold   = "\033[1m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Cyan   = "\033[36m"
	Magenta= "\033[35m"
	Gray   = "\033[90m"
)

// C wraps s in the given color.
func C(color, s string) string { return color + s + Reset }

// Token builds a unique XSS canary, e.g. xsh-a1b2c3d4ef.
func Token() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "xsh" + hex.EncodeToString(b)
}

// IsStdinPiped reports whether STDIN has data attached to the pipe.
func IsStdinPiped() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice == 0
}

// Sleep waits for a random duration between min and max.
func Sleep(min, max time.Duration) {
	if max <= 0 {
		max = min
	}
	if max <= min {
		time.Sleep(min)
		return
	}
	spread := int64(max - min)
	if spread <= 0 {
		time.Sleep(min)
		return
	}
	time.Sleep(min + time.Duration(rand_int(spread))*time.Nanosecond)
}

// rand_int returns a pseudo-random int64 floor in [0, n).
func rand_int(n int64) int64 {
	var x int64
	b := make([]byte, 8)
	if _, err := rand.Read(b); err == nil {
		x = int64(b[0]) | int64(b[1])<<8 | int64(b[2])<<16 | int64(b[3])<<24 |
			int64(b[4])<<32 | int64(b[5])<<40 | int64(b[6])<<48 | int64(b[7])<<56
	}
	if x < 0 {
		x = -x
	}
	return x % n
}

// Response is a normalized audit HTTP response.
type Response struct {
	Status   int
	Header   http.Header
	Body     string
	Duration time.Duration
	WAF      []string
}

// HTTP is the shared client used by every request in the audit pipeline.
type HTTP struct {
	Client  *http.Client
	Headers map[string]string
	Cookies map[string]string
	Verbose bool
	retries int
}

// NewHTTP builds a client with a browser-like default User-Agent.
func NewHTTP(timeout time.Duration, cookies, headers map[string]string, verbose bool) *HTTP {
	if timeout < 8*time.Second {
		timeout = 30 * time.Second
	}
	h := &HTTP{
		Client: &http.Client{Timeout: timeout},
		Cookies: map[string]string{},
		Headers: map[string]string{},
		Verbose: verbose,
	}
	for k, v := range headers {
		h.Headers[k] = v
	}
	if _, ok := h.Headers["User-Agent"]; !ok {
		h.Headers["User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 xsshunts/" + config.Version
	}
	if _, ok := h.Headers["Accept-Language"]; !ok {
		h.Headers["Accept-Language"] = "en-US,en;q=0.9"
	}
	for k, v := range cookies {
		h.Cookies[k] = v
	}
	return h
}

// Do performs request method=url with raw body ("" for GET) and optional extra
// headers. 429 responses trigger exponential backoff with retry.
func (h *HTTP) Do(method, rawurl, body string, extra map[string]string) (*Response, error) {
	method = strings.ToUpper(method)
	if method == "" {
		method = http.MethodGet
	}
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		req, err := http.NewRequest(method, rawurl, strings.NewReader(body))
		if err != nil {
			return nil, err
		}
		for k, v := range h.Headers {
			req.Header.Set(k, v)
		}
		for k, v := range extra {
			req.Header.Set(k, v)
		}
		if len(h.Cookies) > 0 {
			req.Header.Set("Cookie", h.cookieHeader())
		}
		if body != "" && req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		start := time.Now()
		resp, err := h.Client.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(time.Duration(attempt+1) * 900 * time.Millisecond)
			continue
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		out := &Response{
			Status: resp.StatusCode,
			Header: resp.Header,
			Body:   string(raw),
			Duration: time.Since(start),
		}
		out.WAF = detection.Detect(resp.Header, out.Body)
		if detection.IsRateLimited(out.Status, resp.Header) {
			wait := time.Duration(1<<attempt) * 4 * time.Second
			if ra := resp.Header.Get("Retry-After"); ra != "" {
				wait = 6 * time.Second
				_ = ra
			}
			time.Sleep(wait)
			continue
		}
		return out, nil
	}
	return nil, fmt.Errorf("request failed after retries: %w", lastErr)
}

// Get is a GET shortcut.
func (h *HTTP) Get(rawurl string, extra map[string]string) (*Response, error) {
	return h.Do(http.MethodGet, rawurl, "", extra)
}

// Post is an urlencoded POST shortcut.
func (h *HTTP) Post(rawurl, body string, extra map[string]string) (*Response, error) {
	return h.Do(http.MethodPost, rawurl, body, extra)
}

func (h *HTTP) cookieHeader() string {
	parts := make([]string, 0, len(h.Cookies))
	for k, v := range h.Cookies {
		parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
	}
	return strings.Join(parts, "; ")
}

// BuildQuery attaches params to a URL, preserving existing ones.
func BuildQuery(rawurl string, params map[string]string) string {
	u, err := url.Parse(rawurl)
	if err != nil {
		return rawurl
	}
	q := u.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// FileLines reads a UTF-8 text file into a trimmed, non-empty line slice.
func FileLines(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, nil
}
