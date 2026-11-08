// Package wordlists embeds built-in parameter wordlists.
package wordlists

import (
	_ "embed"
	"strings"
)

//go:embed common.txt
var rawCommon string

// Common returns the embedded common parameter wordlist.
func Common() []string {
	return parse(rawCommon)
}

func parse(content string) []string {
	var out []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// ParseFileContent parses an external wordlist file's content (deduplicated, comments skipped).
func ParseFileContent(content string) []string {
	seen := map[string]bool{}
	var out []string
	for _, line := range parse(content) {
		if seen[line] {
			continue
		}
		seen[line] = true
		out = append(out, line)
	}
	return out
}
