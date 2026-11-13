// Package logger renders xsshunts console output (banner, progress, test blocks).
package logger

import (
	"fmt"
	"os"
	"strings"

	"github.com/zapstiko/xsshunts/appmeta"
)

// ANSI color constants (kept close to XSSRush's palette).
const (
	Reset      = "\033[0m"
	Bold       = "\033[1m"
	Dim        = "\033[2m"
	Red        = "\033[31m"
	Green      = "\033[32m"
	Yellow     = "\033[33m"
	Cyan       = "\033[36m"
	White      = "\033[37m"
	Grey       = "\033[90m"
	DarkRed    = "\033[38;5;124m"
	BrightRed  = "\033[1;31m"
	PureWhite  = "\033[97m"
	SoftTeal   = "\033[38;5;116m"
	SoftSlate  = "\033[38;5;110m"
	SoftOrange = "\033[38;5;208m"
)

// FormatConfidence colors a confidence score by severity.
func FormatConfidence(conf float64) string {
	var color string
	switch {
	case conf < 1.0:
		color = Grey
	case conf < 4.0:
		color = Yellow
	case conf < 7.0:
		color = SoftOrange
	default:
		color = BrightRed
	}
	return fmt.Sprintf("%s%.2f%s", color, conf, Reset)
}

// Logger is the shared console logger.
type Logger struct {
	Verbose           bool
	Silent            bool
	currentParamGroup [2]string
}

// NewLogger creates a logger; when silent is true most output is suppressed.
func NewLogger(verbose, silent bool) *Logger {
	return &Logger{Verbose: verbose, Silent: silent}
}

// PrintBanner renders the tool banner. It is shown in silent mode too, while
// progress output remains suppressed.
func (l *Logger) PrintBanner() {
	indentBanner := strings.Repeat(" ", 18)
	indentSub := strings.Repeat(" ", 22)

	for _, line := range appmeta.BannerLines() {
		fmt.Printf("%s%s%s%s\n", DarkRed, indentBanner, line, Reset)
	}
	fmt.Println()
	fmt.Printf("%s%s%s - %s%s\n", PureWhite, indentSub, appmeta.App, appmeta.Description, Reset)
	fmt.Printf("%s%sgithub.com/zapstiko/xsshunts%s\n", PureWhite, indentSub, Reset)
	fmt.Println()
}

// Info prints a neutral info line.
func (l *Logger) Info(msg string) {
	if l.Silent {
		return
	}
	fmt.Printf("[*] %s\n", msg)
}

// Action prints an action line and resets the parameter group.
func (l *Logger) Action(msg string) {
	if l.Silent {
		return
	}
	l.currentParamGroup = [2]string{}
	fmt.Printf("[*] %s\n", msg)
}

// Success prints a green progress line.
func (l *Logger) Success(msg string) {
	if l.Silent {
		return
	}
	fmt.Printf("%s%s[+]%s %s\n", Bold, Green, Reset, msg)
}

// Neutral prints a dim negative line.
func (l *Logger) Neutral(msg string) {
	if l.Silent {
		return
	}
	fmt.Printf("%s[-]%s %s\n", Dim, Reset, msg)
}

// Warning prints a yellow warning line.
func (l *Logger) Warning(msg string) {
	if l.Silent {
		return
	}
	fmt.Printf("%s%s[!]%s %s\n", Bold, Yellow, Reset, msg)
}

// Error prints a red error line to stderr (always shown).
func (l *Logger) Error(msg string) {
	fmt.Fprintf(os.Stderr, "%s%s[-]%s %s\n", Bold, Red, Reset, msg)
}

// CharMatrix prints the special-character reflection matrix summary.
func (l *Logger) CharMatrix(paramName string, matrix map[string]string) {
	if l.Silent {
		return
	}
	var allowed, escaped, filtered []string
	for ch, status := range matrix {
		switch status {
		case "allowed":
			allowed = append(allowed, ch)
		case "escaped":
			escaped = append(escaped, ch)
		case "filtered":
			filtered = append(filtered, ch)
		}
	}
	var parts []string
	if len(allowed) > 0 {
		parts = append(parts, fmt.Sprintf("%sallowed: [ %s ]%s", Green, strings.Join(allowed, " "), Reset))
	}
	if len(escaped) > 0 {
		parts = append(parts, fmt.Sprintf("%sescaped: [ %s ]%s", Yellow, strings.Join(escaped, " "), Reset))
	}
	if len(filtered) > 0 {
		parts = append(parts, fmt.Sprintf("%sfiltered: [ %s ]%s", Red, strings.Join(filtered, " "), Reset))
	}
	if len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%sno reflection detected%s", Dim, Reset))
	}
	fmt.Printf("  %s[*] character matrix for '%s': %s%s\n", SoftSlate, paramName, strings.Join(parts, " | "), Reset)
}

// StartParamTest prints a parameter test header once per (param, method) group.
func (l *Logger) StartParamTest(paramName string, method, context string) {
	if l.Silent {
		return
	}
	groupKey := [2]string{paramName, method}
	if groupKey == l.currentParamGroup {
		return
	}
	l.currentParamGroup = groupKey
	paramDisplay := fmt.Sprintf("'%s'", paramName)
	if paramName == "" {
		paramDisplay = "[URL/Path]"
	}
	ctxStr := ""
	if context != "" {
		ctxStr = fmt.Sprintf(" (context: %s)", context)
	}
	fmt.Printf("[*] testing parameter %s%s%s [%s]%s\n\n", SoftTeal, paramDisplay, Reset, method, ctxStr)
}

// Trying prints a transient "trying payload" status line in silent mode. The
// next attempt overwrites it and findings clear it, so only valid findings stay.
func (l *Logger) Trying(payloadName, payloadStr string) {
	if !l.Silent {
		return
	}
	line := fmt.Sprintf("[*] trying payload: %s (%s)", payloadName, payloadStr)
	line = strings.NewReplacer("\n", " ", "\r", " ").Replace(line)
	if len(line) > 130 {
		line = line[:127] + "..."
	}
	fmt.Printf("\r\033[2K%s%s%s", Dim, line, Reset)
}

// ClearStatus erases the transient silent-mode status line.
func (l *Logger) ClearStatus() {
	if !l.Silent {
		return
	}
	fmt.Print("\r\033[2K")
}

// TestBlockOpts carries the fields of a test block printout.
type TestBlockOpts struct {
	Method      string
	ParamName   string
	Context     string
	PayloadName string
	PayloadStr  string
	RequestDesc string
	Confidence  float64
	Dialog      string
	IsXSS       bool
	IsMatch     bool
	Postfields  string
	HeaderInfo  string
}

// TestBlock renders one payload test result.
func (l *Logger) TestBlock(o TestBlockOpts) {
	if l.Silent {
		if o.IsXSS {
			l.ClearStatus()
			tag := fmt.Sprintf("%s%s[CRITICAL]%s", Bold, Red, Reset)
			fmt.Printf("%s %s\n", tag, o.RequestDesc)
			fmt.Printf("  Payload    : %s (%s%s%s)\n", o.PayloadName, Yellow, o.PayloadStr, Reset)
			if o.Postfields != "" {
				fmt.Printf("  Postfields : %s\n", o.Postfields)
			}
			if o.HeaderInfo != "" {
				fmt.Printf("  Header     : %s\n", o.HeaderInfo)
			}
			fmt.Printf("  Confidence : %s\n\n", FormatConfidence(o.Confidence))
			return
		}
		if o.IsMatch {
			l.ClearStatus()
			tag := fmt.Sprintf("%s%s[POTENTIAL]%s", Bold, SoftOrange, Reset)
			extra := ""
			if o.Postfields != "" {
				extra = fmt.Sprintf(" | Postfields: %s", o.Postfields)
			} else if o.HeaderInfo != "" {
				extra = fmt.Sprintf(" | Header: %s", o.HeaderInfo)
			}
			fmt.Printf("%s %s%s\n", tag, o.RequestDesc, extra)
		}
		return
	}

	groupKey := [2]string{o.ParamName, o.Method}
	if groupKey != l.currentParamGroup {
		l.StartParamTest(o.ParamName, o.Method, o.Context)
	}

	confStr := FormatConfidence(o.Confidence)

	var tag string
	if o.IsXSS {
		fmt.Printf("%s%s[CRITICAL]%s\n", Bold, Red, Reset)
		tag = fmt.Sprintf("%s%s[+]%s", Bold, Red, Reset)
	} else if o.IsMatch {
		fmt.Printf("%s%s[POTENTIAL]%s\n", Bold, SoftOrange, Reset)
		tag = fmt.Sprintf("%s%s[+]%s", Bold, SoftOrange, Reset)
	} else {
		tag = fmt.Sprintf("%s[+]%s", PureWhite, Reset)
	}

	fmt.Printf("  %s Payload    : %s (%s%s%s)\n", tag, o.PayloadName, Yellow, o.PayloadStr, Reset)
	fmt.Printf("  %s Request    : %s%s%s\n", tag, SoftSlate, o.RequestDesc, Reset)
	if o.Postfields != "" {
		fmt.Printf("  %s Postfields : %s%s%s\n", tag, SoftSlate, o.Postfields, Reset)
	}
	if o.HeaderInfo != "" {
		fmt.Printf("  %s Header     : %s%s%s\n", tag, SoftSlate, o.HeaderInfo, Reset)
	}
	fmt.Printf("  %s Confidence : %s\n\n", tag, confStr)
}

// Debug prints verbose debugging output.
func (l *Logger) Debug(msg string) {
	if l.Silent || !l.Verbose {
		return
	}
	fmt.Printf("%s[DEBUG] %s%s\n", Dim, msg, Reset)
}
