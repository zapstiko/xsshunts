package utils

import (
	"regexp"
	"strings"

	xhtml "golang.org/x/net/html"

	"github.com/zapstiko/xsshunts/payloads"
)

// ParseHTML parses an HTML document body (tolerant parsing).
func ParseHTML(content string) *xhtml.Node {
	node, err := xhtml.Parse(strings.NewReader(content))
	if err != nil {
		return nil
	}
	return node
}

// AllElements walks the tree collecting elements matching tagName.
func AllElements(root *xhtml.Node, tagName string) []*xhtml.Node {
	var out []*xhtml.Node
	var walk func(*xhtml.Node)
	walk = func(n *xhtml.Node) {
		if n == nil {
			return
		}
		if n.Type == xhtml.ElementNode && n.Data == tagName {
			out = append(out, n)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(root)
	return out
}

// GetAttr returns an attribute value from an element node.
func GetAttr(n *xhtml.Node, key string) string {
	if n == nil {
		return ""
	}
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

// ElementText concatenates all descendant text of a node.
func ElementText(n *xhtml.Node) string {
	var b strings.Builder
	var walk func(*xhtml.Node)
	walk = func(node *xhtml.Node) {
		if node == nil {
			return
		}
		if node.Type == xhtml.TextNode {
			b.WriteString(node.Data)
		}
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return b.String()
}

// renderChildren serializes children of node into HTML.
func renderChildren(n *xhtml.Node) string {
	var b strings.Builder
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		renderNode(&b, c)
	}
	return b.String()
}

// renderNode serializes a node (element or text) into HTML.
func renderNode(b *strings.Builder, n *xhtml.Node) {
	switch n.Type {
	case xhtml.TextNode:
		b.WriteString(xhtml.EscapeString(n.Data))
	case xhtml.ElementNode:
		b.WriteString("<" + n.Data)
		for _, a := range n.Attr {
			b.WriteString(" " + a.Key + `="` + a.Val + `"`)
		}
		if n.FirstChild == nil {
			b.WriteString("/>")
			return
		}
		b.WriteString(">")
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			renderNode(b, c)
		}
		b.WriteString("</" + n.Data + ">")
	}
}

// FirstDescendantElement returns the first element child.
func FirstDescendantElement(n *xhtml.Node) *xhtml.Node {
	if n == nil {
		return nil
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == xhtml.ElementNode {
			return c
		}
	}
	return nil
}

// GetRenderedPayloadVariants computes browser-normalized payload variants.
func GetRenderedPayloadVariants(payload string) []string {
	seen := map[string]bool{payload: true}
	variants := []string{payload}

	root := ParseHTML("<div>" + payload + "</div>")
	var div *xhtml.Node
	for _, el := range AllElements(root, "div") {
		div = el
		break
	}
	if div != nil {
		inner := renderChildren(div)
		if inner != "" && !seen[inner] {
			seen[inner] = true
			variants = append(variants, inner)
		}
		if first := FirstDescendantElement(div); first != nil {
			var b strings.Builder
			renderNode(&b, first)
			serialized := b.String()
			if serialized != "" && !seen[serialized] {
				seen[serialized] = true
				variants = append(variants, serialized)
			}
		}
	}
	return variants
}

var tagExtractRe = regexp.MustCompile(`<([a-zA-Z0-9]+)`)

var dialogHostTags = map[string]bool{
	"img": true, "svg": true, "body": true, "iframe": true, "input": true,
	"button": true, "video": true, "audio": true, "details": true,
}

// DetectMatch attempts to confirm a payload exists in rendered HTML without dialog execution.
func DetectMatch(renderedHTML string, p *payloads.PayloadData) bool {
	if !p.CheckForMatchEnabled() {
		return false
	}
	renderedLower := strings.ToLower(renderedHTML)
	payloadLower := strings.ToLower(p.Payload)

	for _, re := range p.MatchPatterns() {
		if re.MatchString(renderedHTML) {
			return true
		}
	}

	for _, variant := range GetRenderedPayloadVariants(p.Payload) {
		if strings.Contains(renderedLower, strings.ToLower(variant)) {
			return true
		}
	}

	root := ParseHTML(renderedHTML)
	expected := fmtInt(p.ExpectedValue)
	dialogType := strings.ToLower(p.DialogType)

	injectedTags := tagExtractRe.FindAllStringSubmatch(payloadLower, -1)
	seenTag := map[string]bool{}
	for _, m := range injectedTags {
		tag := strings.ToLower(m[1])
		if seenTag[tag] {
			continue
		}
		seenTag[tag] = true

		for _, el := range AllElements(root, tag) {
			if dialogHostTags[tag] {
				for _, attr := range el.Attr {
					name := strings.ToLower(attr.Key)
					if !strings.HasPrefix(name, "on") {
						continue
					}
					val := strings.ToLower(attr.Val)
					if strings.Contains(val, dialogType) && (expected == "" || strings.Contains(val, expected)) {
						return true
					}
				}
			} else if tag == "script" {
				hasMatchingAttr := false
				for _, attr := range el.Attr {
					if strings.Contains(payloadLower, strings.ToLower(attr.Key)) {
						hasMatchingAttr = true
					}
				}
				text := ElementText(el)
				var cleanLines []string
				for _, line := range strings.Split(text, "\n") {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*") {
						continue
					}
					cleanLines = append(cleanLines, line)
				}
				cleanText := strings.ToLower(strings.Join(cleanLines, " "))
				hasTagPrefix := strings.Contains(payloadLower, "<"+tag)
				if (hasMatchingAttr || hasTagPrefix) && strings.Contains(cleanText, dialogType) &&
					(expected == "" || strings.Contains(cleanText, expected)) {
					return true
				}
			}
		}
	}
	return false
}

func fmtInt(v int) string {
	if v == 0 {
		return ""
	}
	digits := []byte{}
	n := v
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// FormField is one control inside an HTML form.
type FormField struct {
	Name  string
	Value string
	Tag   string
}

// FormInfo summarizes one <form> element.
type FormInfo struct {
	Method    string
	Action    string
	Fields    []FormField
	FieldTags []string
}

// CollectForms extracts form elements with their controls.
func CollectForms(root *xhtml.Node) []*FormInfo {
	var forms []*FormInfo
	for _, form := range AllElements(root, "form") {
		info := &FormInfo{
			Method: strings.ToUpper(GetAttr(form, "method")),
			Action: GetAttr(form, "action"),
		}
		if info.Method == "" {
			info.Method = "GET"
		}
		for c := form.FirstChild; c != nil; c = c.NextSibling {
			visitControlTree(c, info)
		}
		forms = append(forms, info)
	}
	return forms
}

var controlTags = map[string]bool{"input": true, "textarea": true, "select": true}

func visitControlTree(n *xhtml.Node, info *FormInfo) {
	if n == nil {
		return
	}
	if n.Type == xhtml.ElementNode && controlTags[n.Data] {
		name := GetAttr(n, "name")
		if name != "" {
			info.Fields = append(info.Fields, FormField{Name: name, Value: GetAttr(n, "value"), Tag: n.Data})
			info.FieldTags = append(info.FieldTags, n.Data)
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		visitControlTree(c, info)
	}
}

// CollectLinks returns all anchor href values in document order.
func CollectLinks(root *xhtml.Node) []string {
	var hrefs []string
	for _, a := range AllElements(root, "a") {
		href := GetAttr(a, "href")
		if href != "" {
			hrefs = append(hrefs, href)
		}
	}
	return hrefs
}

// CollectScriptTexts returns the inline text of all <script> tags.
func CollectScriptTexts(root *xhtml.Node) []string {
	var texts []string
	for _, s := range AllElements(root, "script") {
		contentPane := ElementText(s)
		if strings.TrimSpace(contentPane) != "" {
			texts = append(texts, contentPane)
		}
	}
	return texts
}
