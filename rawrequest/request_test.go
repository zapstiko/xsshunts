package rawrequest

import (
	"strings"
	"testing"
)

func TestParseGETRequest(t *testing.T) {
	raw := "GET /search?q=test&page=1 HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"User-Agent: Burp-Test/1.0\r\n" +
		"Cookie: session=abc; role=admin\r\n" +
		"Accept: text/html\r\n" +
		"Connection: close\r\n" +
		"\r\n"

	req, err := Parse([]byte(raw), "")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if req.Method != "GET" {
		t.Fatalf("method = %q, want GET", req.Method)
	}
	if req.URL != "https://example.com/search?q=test&page=1" {
		t.Fatalf("url = %q", req.URL)
	}
	if req.UserAgent != "Burp-Test/1.0" {
		t.Fatalf("user-agent = %q", req.UserAgent)
	}
	if len(req.Cookies) != 2 || req.Cookies[0].Name != "session" || req.Cookies[1].Value != "admin" {
		t.Fatalf("cookies = %+v", req.Cookies)
	}
	if req.Headers["Accept"] != "text/html" {
		t.Fatalf("expected Accept header, got %+v", req.Headers)
	}
	for key := range req.Headers {
		switch strings.ToLower(key) {
		case "host", "cookie", "user-agent", "connection":
			t.Fatalf("header %q should not be forwarded", key)
		}
	}
}

func TestParsePOSTFormRequest(t *testing.T) {
	raw := "POST /submit?x=1 HTTP/1.1\n" +
		"Host: 127.0.0.1:18081\n" +
		"Content-Type: application/x-www-form-urlencoded\n" +
		"Content-Length: 19\n" +
		"X-Custom: yes\n" +
		"\n" +
		"q=hello&page=2"

	req, err := Parse([]byte(raw), "")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if req.URL != "http://127.0.0.1:18081/submit?x=1" {
		t.Fatalf("url = %q", req.URL)
	}
	if req.Method != "POST" {
		t.Fatalf("method = %q", req.Method)
	}
	if req.Postfields["q"] != "hello" || req.Postfields["page"] != "2" {
		t.Fatalf("postfields = %+v", req.Postfields)
	}
	if req.Headers["X-Custom"] != "yes" {
		t.Fatalf("custom header missing: %+v", req.Headers)
	}
	if req.UnsupportedBody != "" {
		t.Fatalf("unexpected body warning: %q", req.UnsupportedBody)
	}
}

func TestParseAbsoluteTargetAndSchemeOverride(t *testing.T) {
	raw := "POST http://internal.example.test/api?q=1 HTTP/1.1\n" +
		"Host: ignored.example.test\n" +
		"Content-Type: application/x-www-form-urlencoded\n" +
		"\n" +
		"name=x"
	req, err := Parse([]byte(raw), "")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if req.URL != "http://internal.example.test/api?q=1" {
		t.Fatalf("url = %q", req.URL)
	}

	raw2 := "GET /path HTTP/1.1\nHost: internal.example.test\n\n"
	req2, err := Parse([]byte(raw2), "http")
	if err != nil {
		t.Fatalf("Parse override: %v", err)
	}
	if req2.URL != "http://internal.example.test/path" {
		t.Fatalf("override url = %q", req2.URL)
	}
}

func TestParseJSONBodyUnsupported(t *testing.T) {
	raw := "POST /api HTTP/1.1\n" +
		"Host: example.com\n" +
		"Content-Type: application/json\n" +
		"\n" +
		`{"q":"hello"}`
	req, err := Parse([]byte(raw), "")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(req.Postfields) != 0 {
		t.Fatalf("JSON body should not produce form fields: %+v", req.Postfields)
	}
	if req.UnsupportedBody == "" {
		t.Fatal("expected an unsupported-body warning for JSON")
	}
}

func TestParseRejectsUnsupportedMethodAndMissingHost(t *testing.T) {
	if _, err := Parse([]byte("PUT /x HTTP/1.1\nHost: a\n\n"), ""); err == nil {
		t.Fatal("expected PUT to be rejected")
	}
	if _, err := Parse([]byte("GET /x HTTP/1.1\n\n"), ""); err == nil {
		t.Fatal("expected missing Host to be rejected")
	}
	if _, err := Parse([]byte(""), ""); err == nil {
		t.Fatal("expected empty request to be rejected")
	}
}

func TestParseDuplicateHeaders(t *testing.T) {
	raw := "GET / HTTP/1.1\nHost: example.com\nX-Test: one\nX-Test: two\n\n"
	req, err := Parse([]byte(raw), "")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if req.Headers["X-Test"] != "one, two" {
		t.Fatalf("duplicate header = %q", req.Headers["X-Test"])
	}
}
