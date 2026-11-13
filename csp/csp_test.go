package csp

import (
	"strings"
	"testing"
)

func TestParseHeaderAndMeta(t *testing.T) {
	headers := map[string]string{
		"Content-Security-Policy":             "script-src 'self' 'nonce-abc123'; base-uri 'none'",
		"Content-Security-Policy-Report-Only": "default-src 'none'",
	}
	html := `<html><head><meta http-equiv="Content-Security-Policy" content="img-src 'self'"></head>
	<body><script nonce="domNonce">x</script></body></html>`

	policy := Parse(headers, html)
	if len(policy.EnforcedHeaders) != 1 || len(policy.MetaPolicies) != 1 || len(policy.ReportOnlyHeaders) != 1 {
		t.Fatalf("unexpected policy parts: %+v", policy)
	}
	if len(policy.Directives["script-src"]) == 0 {
		t.Fatalf("script-src not parsed: %+v", policy.Directives)
	}
	foundNonce := false
	for _, nonce := range policy.Nonces {
		if nonce == "abc123" || nonce == "domNonce" {
			foundNonce = true
		}
	}
	if !foundNonce {
		t.Fatalf("nonces not collected: %v", policy.Nonces)
	}
}

func TestAnalyzeUnsafeInline(t *testing.T) {
	p := &Policy{
		EnforcedHeaders: []string{"script-src 'self' 'unsafe-inline' 'unsafe-eval'"},
		Directives:      map[string][]string{},
	}
	parseDirectives(p.EnforcedHeaders[0], p.Directives)
	a := Analyze(p)
	if !a.Enforced || !a.InlineAllowed || !a.UnsafeEval {
		t.Fatalf("flags wrong: %+v", a)
	}
	assertTechnique(t, a, "unsafe_inline")
	assertTechnique(t, a, "unsafe_eval")
	if len(a.Issues) == 0 {
		t.Fatal("expected CSP issues")
	}
}

func TestAnalyzeReportOnly(t *testing.T) {
	p := &Policy{ReportOnlyHeaders: []string{"default-src 'none'"}, Directives: map[string][]string{}}
	a := Analyze(p)
	if !a.Present || a.Enforced || !a.ReportOnlyOnly {
		t.Fatalf("report-only state wrong: %+v", a)
	}
	assertTechnique(t, a, "report_only")
	if len(BypassPayloads(a, true)) != 0 {
		t.Fatal("report-only CSP should not require bypass payload tests")
	}
}

func TestNonceReusePayload(t *testing.T) {
	p := Parse(map[string]string{
		"Content-Security-Policy": "script-src 'nonce-abc123' 'strict-dynamic'",
	}, "")
	a := Analyze(p)
	if len(a.Nonces) == 0 {
		t.Fatal("nonce not detected")
	}
	payloads := BypassPayloads(a, false)
	if len(payloads) == 0 {
		t.Fatal("expected nonce bypass payload")
	}
	if payloads[0].Key != "nonce_reuse" || !strings.Contains(payloads[0].Payload, `nonce="abc123"`) {
		t.Fatalf("unexpected payload: %+v", payloads[0])
	}
	assertTechnique(t, a, "nonce_reuse")
	assertTechnique(t, a, "strict_dynamic")
}

func TestDataURIPayload(t *testing.T) {
	p := &Policy{
		EnforcedHeaders: []string{"script-src 'self' data:"},
		Directives:      map[string][]string{},
	}
	parseDirectives(p.EnforcedHeaders[0], p.Directives)
	a := Analyze(p)
	payloads := BypassPayloads(a, false)
	found := false
	for _, payload := range payloads {
		if payload.Key == "data_uri" && strings.Contains(payload.Payload, "data:text/javascript") {
			found = true
		}
	}
	if !found {
		t.Fatalf("data payload missing: %+v", payloads)
	}
	assertTechnique(t, a, "data_uri")
}

func TestAngularCDNDetection(t *testing.T) {
	p := &Policy{
		EnforcedHeaders: []string{"script-src 'self' https://cdnjs.cloudflare.com"},
		Directives:      map[string][]string{},
	}
	parseDirectives(p.EnforcedHeaders[0], p.Directives)
	a := Analyze(p)
	if a.AngularURL == "" || !strings.Contains(a.AngularURL, "angular") {
		t.Fatalf("angular CDN not detected: %+v", a)
	}
	payloads := BypassPayloads(a, false)
	hasAngular := false
	for _, payload := range payloads {
		if payload.Key == "angular_cdn" && strings.Contains(payload.Payload, "ng-app") {
			hasAngular = true
		}
	}
	if !hasAngular {
		t.Fatalf("angular payload missing: %+v", payloads)
	}
	assertTechnique(t, a, "angular_cdn")
}

func TestMissingBaseURIAndWildcard(t *testing.T) {
	p := &Policy{
		EnforcedHeaders: []string{"script-src *"},
		Directives:      map[string][]string{},
	}
	parseDirectives(p.EnforcedHeaders[0], p.Directives)
	a := Analyze(p)
	if !a.Wildcard || !a.MissingBaseURI || !a.MissingObjectSrc {
		t.Fatalf("expected wildcard and missing directives: %+v", a)
	}
	assertTechnique(t, a, "wildcard")
	assertTechnique(t, a, "base_uri")
	assertTechnique(t, a, "object_src")
}

func TestAllTechniques(t *testing.T) {
	techniques := AllTechniques()
	if len(techniques) < 15 {
		t.Fatalf("knowledge base too small: %d", len(techniques))
	}
	for _, technique := range techniques {
		if technique.Key == "" || technique.Name == "" || len(technique.Payloads) == 0 {
			t.Fatalf("incomplete technique: %+v", technique)
		}
	}
}

func assertTechnique(t *testing.T, a *Analysis, key string) {
	t.Helper()
	for _, technique := range a.Techniques {
		if technique.Key == key {
			return
		}
	}
	t.Fatalf("technique %q not selected: %+v", key, a.Techniques)
}
