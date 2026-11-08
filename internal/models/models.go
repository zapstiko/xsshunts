// Package models defines the shared data structures used across xsshunts.
package models

import (
	"fmt"
	"strings"
	"time"
)

// Scan vectors supported by the tool.
const (
	VectorGet      = "get"
	VectorPost     = "post"
	VectorPath     = "path"
	VectorFragment = "fragment"
	VectorHeader   = "header"
)

// Injection contexts for reflected content.
const (
	ContextHTML       = "html"
	ContextAttribute  = "attribute"
	ContextJavascript = "javascript"
	ContextURL        = "url"
	ContextUnknown    = "unknown"
)

// Confirmation levels for findings.
const (
	ConfirmDialog     = "dialog"     // payload executed in a real browser (near-zero false positives)
	ConfirmReflection = "reflection" // payload mirrored in the raw response
)

// Target is a single endpoint to audit.
type Target struct {
	Method string
	URL    string
	Data   string // raw POST body (when supplied by the operator)
	Depth  int
}

// Param is a discoverable injectable parameter.
type Param struct {
	Name    string
	Value   string
	Source  string // get | form | jsvar | hidden | manual
	Context string // forced via -p, otherwise detected by reflection analysis
	Tag     string
	Attr    string
}

// FormField is a single form control.
type FormField struct {
	Name  string
	Type  string
	Value string
}

// Form is a parsed HTML form.
type Form struct {
	BaseURL string
	Action  string
	Method  string
	Fields  []FormField
}

// Reflection describes where and how a canary token was mirrored by the target.
type Reflection struct {
	URL      string
	Param    string
	Source   string // get | post | path | header | fragment
	Context  string
	Tag      string
	Attr     string
	Allowed  []string // special characters reflected raw
	Escaped  []string // special characters reflected HTML-escaped
	Filtered []string // special characters removed by the target
}

// Finding is a reported XSS vulnerability.
type Finding struct {
	Method       string            `json:"method"`
	URL          string            `json:"url"`
	Vector       string            `json:"vector"`
	Parameter    string            `json:"parameter"`
	Payload      string            `json:"payload"`
	Context      string            `json:"context,omitempty"`
	Confirmation string            `json:"confirmation"`
	Dialog       string            `json:"dialog,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	Evidence     string            `json:"evidence,omitempty"`
	Severity     string            `json:"severity"`
	DiscoveredAt time.Time         `json:"discovered_at"`
}

// IsVulnerable reports whether the finding was browser-confirmed.
func (f Finding) IsVulnerable() bool { return f.Confirmation == ConfirmDialog }

// Describe renders a human-readable reflection description for the console.
func (r *Reflection) Describe() string {
	if r == nil {
		return ""
	}
	desc := fmt.Sprintf("reflects in %s context", strings.ToUpper(r.Context))
	if r.Tag != "" {
		desc += fmt.Sprintf(" (tag: <%s>)", r.Tag)
	}
	if r.Attr != "" {
		desc += fmt.Sprintf(" (attribute: %s)", r.Attr)
	}
	return desc
}

// MatrixLine renders the special-character reflection matrix row.
func (r *Reflection) MatrixLine() string {
	if r == nil {
		return ""
	}
	var parts []string
	if len(r.Allowed) > 0 {
		parts = append(parts, "allowed: [ "+strings.Join(r.Allowed, " ")+" ]")
	}
	if len(r.Escaped) > 0 {
		parts = append(parts, "escaped: [ "+strings.Join(r.Escaped, " ")+" ]")
	}
	if len(r.Filtered) > 0 {
		parts = append(parts, "filtered: [ "+strings.Join(r.Filtered, " ")+" ]")
	}
	if len(parts) == 0 {
		return "character matrix: no reflection detected"
	}
	return "characters: " + strings.Join(parts, " | ")
}
