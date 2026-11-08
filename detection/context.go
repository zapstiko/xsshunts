// Package detection implements reflection/context/matrix/WAF analysis engines.
package detection

import (
	"strings"

	"github.com/zapstiko/xsshunts/payloads"
)

// ContextAliases maps CLI contexts to engine context names.
var ContextAliases = map[string]string{
	"js":          "javascript",
	"javascript":  "javascript",
	"html":        "html",
	"attr":        "attribute",
	"attribute":   "attribute",
	"url":         "url",
	"dom":         "dom_js_html",
	"dom_js_html": "dom_js_html",
}

// NormalizeContextName normalizes a user-provided context name.
func NormalizeContextName(rawContext string) string {
	if strings.TrimSpace(rawContext) == "" {
		return ""
	}
	cleaned := strings.ToLower(strings.TrimSpace(rawContext))
	if mapped, ok := ContextAliases[cleaned]; ok {
		return mapped
	}
	return cleaned
}

// ResolveContextName picks the testing context for a parameter location.
func ResolveContextName(rawContext, location string) string {
	if rawContext == "html" && location == "DOM" {
		return "dom_js_html"
	}
	if rawContext == "unknown" {
		if location == "DOM" {
			return "dom_js_html"
		}
		return "html"
	}
	if rawContext == "" {
		return "html"
	}
	return rawContext
}

// GetPayloadKeysForContext returns the payload list for a context (html fallback).
func GetPayloadKeysForContext(contextName string) []string {
	if list, ok := payloads.ContextMap[contextName]; ok {
		return list
	}
	return payloads.ContextMap["html"]
}
