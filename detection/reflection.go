package detection

import (
	"regexp"
)

// URLAttrRegex matches URL-ish attribute openings at the tail of a tag snippet.
var URLAttrRegex = regexp.MustCompile(`(?i)(href|src|action|formaction|data|poster)\s*=\s*["'][^"']*$`)

// AttrRegex matches any attribute opening at the tail of a tag snippet.
var AttrRegex = regexp.MustCompile(`(?i)\w+\s*=\s*["'][^"']*$`)

// TagRegex extracts `<name ...attr...` tag openings.
var TagRegex = regexp.MustCompile(`<([a-zA-Z0-9]+)([^>]*)`)

// Reflection is one detected reflection observation.
type Reflection struct {
	Context string
	Tags    string
}

// DetectAllReflections finds every occurrence of value inside html and classifies
// its syntactic context (html / attribute / javascript / url / unknown).
func DetectAllReflections(htmlContent, value string) []Reflection {
	var reflections []Reflection
	if value == "" || htmlContent == "" {
		return reflections
	}

	index := 0
	valLen := len(value)

	for {
		pos := firstIndex(htmlContent, value, index)
		if pos == -1 {
			break
		}

		before := htmlContent[:pos]

		context := "unknown"
		tags := ""

		tagMatches := TagRegex.FindAllStringSubmatch(before, -1)
		if len(tagMatches) > 0 {
			lastTag := tagMatches[len(tagMatches)-1]
			tagName := lower(lastTag[1])
			tagAttributes := lastTag[2]

			tags = tagName

			switch {
			case tagName == "script":
				context = "javascript"
			case URLAttrRegex.MatchString(tagAttributes):
				context = "url"
			case AttrRegex.MatchString(tagAttributes):
				context = "attribute"
			default:
				context = "html"
			}
		}

		reflections = append(reflections, Reflection{Context: context, Tags: tags})
		index = pos + valLen
	}

	return reflections
}

// firstIndex finds needle in haystack at or after start.
func firstIndex(haystack, needle string, start int) int {
	if start >= len(haystack) {
		return -1
	}
	idx := stringsIdx(haystack[start:], needle)
	if idx == -1 {
		return -1
	}
	return start + idx
}

// stringsIdx is strings.Index without importing strings here twice.
func stringsIdx(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}
