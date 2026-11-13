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

func TestBlobAndUnsafeHashes(t *testing.T) {
	p := Parse(map[string]string{
		"Content-Security-Policy": "script-src 'self' blob: 'unsafe-hashes'",
	}, "")
	a := Analyze(p)
	if !a.BlobAllowed || !a.UnsafeHashes {
		t.Fatalf("scheme/hash flags missing: %+v", a)
	}
	assertTechnique(t, a, "blob_uri")
	assertTechnique(t, a, "unsafe_hashes")
}

func TestAngularInPage(t *testing.T) {
	p := Parse(map[string]string{
		"Content-Security-Policy": "script-src 'self'",
	}, `<html><body><div ng-app ng-csp>{{1+1}}</div></body></html>`)
	a := Analyze(p)
	if !a.AngularInPage {
		t.Fatalf("in-page Angular not detected: %+v", a)
	}
	assertTechnique(t, a, "angular_dom")
	payloads := BypassPayloads(a, false)
	found := false
	for _, payload := range payloads {
		if payload.Key == "angular_dom" && strings.Contains(payload.Payload, "ng-app") && !strings.Contains(payload.Payload, "<script src") {
			found = true
		}
	}
	if !found {
		t.Fatalf("in-page angular payload missing: %+v", payloads)
	}
}

func TestWildcardSubdomain(t *testing.T) {
	p := Parse(map[string]string{
		"Content-Security-Policy": "script-src 'self' https://*.example.com; frame-src https://frames.example.com",
	}, "")
	a := Analyze(p)
	if len(a.WildcardHosts) == 0 || a.WildcardHosts[0] != "example.com" {
		t.Fatalf("wildcard hosts not detected: %+v", a.WildcardHosts)
	}
	assertTechnique(t, a, "wildcard_subdomain_takeover")
	assertTechnique(t, a, "frame_src_allowlist")
}

func TestTrustedTypesReportOnly(t *testing.T) {
	p := Parse(map[string]string{
		"Content-Security-Policy":             "script-src 'self'",
		"Content-Security-Policy-Report-Only": "require-trusted-types-for 'script'; trusted-types dompurify",
	}, "")
	a := Analyze(p)
	if !a.TrustedTypesReportOnly {
		t.Fatalf("report-only Trusted Types not detected: %+v", a)
	}
	assertTechnique(t, a, "trusted_types_report_only")
}

func TestPHPAndReportEndpoint(t *testing.T) {
	p := Parse(map[string]string{
		"Content-Security-Policy": "script-src 'self'; report-uri /csp-report",
		"X-Powered-By":            "PHP/8.3.0",
	}, "")
	a := Analyze(p)
	if !a.PHP || !a.HasReport {
		t.Fatalf("PHP/report flags missing: %+v", a)
	}
	assertTechnique(t, a, "php_header_strip")
	assertTechnique(t, a, "csp_report_exfil")
}

func TestExpandedTechniqueCategories(t *testing.T) {
	techniques := AllTechniques()
	if len(techniques) < 35 {
		t.Fatalf("expected an expanded knowledge base, got %d techniques", len(techniques))
	}
	categories := map[string]bool{}
	for _, technique := range techniques {
		categories[CategoryFor(technique.Key)] = true
	}
	if len(categories) < 8 {
		t.Fatalf("expected multiple categories, got %d: %v", len(categories), categories)
	}
}
