package modules

import (
	"strings"

	"github.com/zapstiko/xsshunts/internal/models"
)

// skip reports whether a parameter name is excluded via -e/--exclude.
func skip(s *Session, param string) bool {
	if param == "" {
		return true
	}
	lower := strings.ToLower(param)
	for _, ex := range strings.Split(s.Opts.Exclude, ",") {
		ex = strings.ToLower(strings.TrimSpace(ex))
		if ex != "" && ex == lower {
			return true
		}
	}
	return false
}

// methodFor maps a vector constant to its report HTTP method label.
func methodFor(vector string) string {
	switch vector {
	case models.VectorPost:
		return "POST"
	case models.VectorPath:
		return "PATH"
	case models.VectorFragment:
		return "FRAGMENT"
	case models.VectorHeader:
		return "HEADER"
	default:
		return "GET"
	}
}
