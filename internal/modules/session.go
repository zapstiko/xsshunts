// Package modules implements xsshunts audit steps: discovery, reflection
// analysis, and the per-vector payload modules (get, post, path, fragment,
// header).
package modules

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/zapstiko/xsshunts/internal/browser"
	"github.com/zapstiko/xsshunts/internal/config"
	"github.com/zapstiko/xsshunts/internal/models"
	"github.com/zapstiko/xsshunts/internal/payloads"
	"github.com/zapstiko/xsshunts/internal/reporter"
	"github.com/zapstiko/xsshunts/internal/utils"
)

// Session carries the shared audit state across every module.
type Session struct {
	Opts    *config.Options
	HTTP    *utils.HTTP
	Report  *reporter.Report
	Browser *browser.Manager

	browserOnce sync.Once
	browserErr  error

	mu       sync.Mutex
	seenKeys map[string]bool
	delayMin time.Duration
	delayMax time.Duration
	wordlist []string
	wafNames map[string]bool

	targetsMu     sync.Mutex
	targetsLookup map[string]bool
}

// NewSession builds the shared session (wordlist, HTTP client, delays).
func NewSession(opts *config.Options, rep *reporter.Report) (*Session, error) {
	s := &Session{
		Opts:          opts,
		Report:        rep,
		seenKeys:      map[string]bool{},
		delayMin:      time.Duration(opts.DelayMinMS) * time.Millisecond,
		delayMax:      time.Duration(opts.DelayMaxMS) * time.Millisecond,
		wordlist:      []string{},
		wafNames:      map[string]bool{},
		targetsLookup: map[string]bool{},
	}
	s.HTTP = utils.NewHTTP(time.Duration(opts.TimeoutMS)*time.Millisecond, opts.CookieMap(), opts.BaseHeaders(), opts.Verbose)
	return s, nil
}

// LoadWordlist returns the override wordlist or the built-in parameter list.
func (s *Session) LoadWordlist() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.wordlist) > 0 {
		return s.wordlist
	}
	if s.Opts.WordlistFile != "" {
		lines, err := utils.FileLines(s.Opts.WordlistFile)
		if err != nil || len(lines) == 0 {
			fmt.Printf("[!] cannot read wordlist %s (%v); falling back to builtin list\n", s.Opts.WordlistFile, err)
		} else {
			s.wordlist = lines
		}
	}
	if len(s.wordlist) == 0 {
		s.wordlist = payloads.KnownParams()
	}
	return s.wordlist
}

// Sleep performs the module-level pacing delay (jittered) so scans respect
// WAFs and rate limits.
func (s *Session) Sleep(delay bool) {
	if !delay {
		return
	}
	s.mu.Lock()
	minimum, maximum := s.delayMin, s.delayMax
	s.mu.Unlock()
	utils.Sleep(minimum, maximum)
}

// EnsureBrowser lazily starts the shared chromium process.
func (s *Session) EnsureBrowser() error {
	s.browserOnce.Do(func() {
		if s.Opts.NoBrowser {
			s.browserErr = errBrowserDisabled
			return
		}
		mgr, berr := browser.New(s.Opts.BrowserPath, s.Opts.BrowserKind, s.Opts.Headless)
		if berr != nil {
			s.browserErr = berr
			return
		}
		s.Browser = mgr
	})
	return s.browserErr
}

// CloseBrowser terminates the browser.
func (s *Session) CloseBrowser() {
	if s.Browser != nil {
		s.Browser.Close()
	}
}

type errBrowserDisabledT struct{}

func (errBrowserDisabledT) Error() string { return "browser confirmation disabled (--no-browser)" }

var errBrowserDisabled = errBrowserDisabledT{}

// Probe wraps a browser probe with disabled/error fallbacks.
func (s *Session) Probe(url string, headers, cookies map[string]string, afterLoadJS string, timeout time.Duration) (*browser.ProbeResult, error) {
	if s.Opts.NoBrowser {
		return nil, errBrowserDisabled
	}
	if err := s.EnsureBrowser(); err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = time.Duration(s.Opts.TimeoutMS) * time.Millisecond
	}
	return s.Browser.Probe(browser.ProbeOptions{
		URL:         url,
		Timeout:     timeout,
		Settle:      2 * time.Second,
		Headers:     headers,
		Cookies:     cookies,
		AfterLoadJS: afterLoadJS,
		CaptureHTML: true,
	})
}

// BrowserAvailable reports whether dialog confirmation can run.
func (s *Session) BrowserAvailable() bool {
	return !s.Opts.NoBrowser && s.EnsureBrowser() == nil
}

// printLocked prints through a mutex so concurrent workers keep readable logs.
func (s *Session) print(color, format string, args ...interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fmt.Printf(color+format+"\n", args...)
}

// Info logs neutral text.
func (s *Session) Info(format string, args ...interface{}) { s.print("", format, args...) }

// Verbose logs with prefix when -v set.
func (s *Session) Verbose(format string, args ...interface{}) {
	if s.Opts.Verbose {
		s.print(utils.Gray, format, args...)
	}
}

// Warn logs attention text.
func (s *Session) Warn(format string, args ...interface{}) {
	s.print(utils.Yellow+"[!] ", format, args...)
}

// Good logs success text.
func (s *Session) Good(format string, args ...interface{}) {
	s.print(utils.Green+"[+] ", format, args...)
}

// Step logs progress text.
func (s *Session) Step(format string, args ...interface{}) {
	s.print(utils.Blue+"[*] ", format, args...)
}

// Candidate logs reflection-only (unconfirmed) hits.
func (s *Session) Candidate(format string, args ...interface{}) {
	s.print(utils.Yellow+"[^] ", format, args...)
}

// AddWAF announces a detected WAF once and doubles pacing delays for the
// remainder of the session.
func (s *Session) AddWAF(names []string) {
	for _, n := range names {
		s.mu.Lock()
		isNew := !s.wafNames[n]
		s.wafNames[n] = true
		if isNew {
			s.delayMin *= 2
			s.delayMax *= 2
		}
		list := make([]string, 0, len(s.wafNames))
		for k := range s.wafNames {
			list = append(list, k)
		}
		s.mu.Unlock()
		if isNew {
			s.Warn("waf detected: %s (request delays doubled)", strings.Join(list, ", "))
			s.Report.WAF = list
		}
	}
}

// AddFinding dedupes and stores one finding; returns true when new.
func (s *Session) AddFinding(f models.Finding) bool {
	key := f.Vector + "|" + f.Parameter + "|" + f.Payload + "|" + f.URL
	s.mu.Lock()
	if s.seenKeys[key] {
		s.mu.Unlock()
		return false
	}
	s.seenKeys[key] = true
	s.mu.Unlock()
	f.DiscoveredAt = time.Now()
	if f.IsVulnerable() {
		s.Report.AddConfirmed(&f)
	} else {
		s.Report.AddCandidate(&f)
	}
	return true
}

// AddTargets dedupes crawl-discovered targets and returns only the fresh ones.
func (s *Session) AddTargets(targets []models.Target) []models.Target {
	s.targetsMu.Lock()
	defer s.targetsMu.Unlock()
	var fresh []models.Target
	for _, t := range targets {
		if !s.targetsLookup[t.URL] {
			s.targetsLookup[t.URL] = true
			fresh = append(fresh, t)
		}
	}
	return fresh
}

// RegisterTarget seeds the target lookup for initial targets.
func (s *Session) RegisterTarget(t models.Target) {
	s.targetsMu.Lock()
	defer s.targetsMu.Unlock()
	s.targetsLookup[t.URL] = true
}
