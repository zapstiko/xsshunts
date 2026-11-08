// Package browser drives real headless browser instances through Playwright
// (firefox/chromium/webkit) and confirms XSS by intercepting JavaScript dialogs.
package browser

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/playwright-community/playwright-go"

	"github.com/zapstiko/xsshunts/config"
	"github.com/zapstiko/xsshunts/models"
)

// Manager owns the Playwright instance and one browser process.
type Manager struct {
	BrowserType string
	Channel     string
	Headless    bool
	TimeoutMS   int
	Headers     map[string]string
	Cookies     []models.CookieEntry

	pw      *playwright.Playwright
	browser playwright.Browser
	mu      sync.Mutex
}

// NewManager creates a browser manager for the given engine.
func NewManager(browserType string, headless bool, timeoutMS int, headers map[string]string, cookies []models.CookieEntry) *Manager {
	typeName := strings.ToLower(browserType)
	if typeName == "" {
		typeName = "firefox"
	}
	return &Manager{
		BrowserType: typeName,
		Channel:     os.Getenv("XSSHUNTS_CHANNEL"),
		Headless:    headless,
		TimeoutMS:   timeoutMS,
		Headers:     copyStringMap(headers),
		Cookies:     append([]models.CookieEntry(nil), cookies...),
	}
}

func copyStringMap(in map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

// EnsureInstalled downloads the Playwright driver and the requested browser.
func EnsureInstalled(browsers ...string) error {
	opts := &playwright.RunOptions{Verbose: false, Browsers: browsers}
	return playwright.Install(opts)
}

// Start launches the browser process, auto-installing missing pieces once.
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.browser != nil {
		return nil
	}

	pw, err := playwright.Run(&playwright.RunOptions{Verbose: false, Stdout: io.Discard})
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "install the driver") {
			if installErr := EnsureInstalled(m.BrowserType); installErr != nil {
				return fmt.Errorf("playwright install failed: %w", installErr)
			}
			pw, err = playwright.Run(&playwright.RunOptions{Verbose: false, Stdout: io.Discard})
		}
		if err != nil {
			return fmt.Errorf("could not start playwright: %w", err)
		}
	}

	engine, err := m.engine(pw)
	if err != nil {
		pw.Stop()
		return err
	}

	browser, err := engine.Launch(m.launchOptions())
	if err != nil {
		// Browser binaries may not be downloaded yet; install and retry once.
		if installErr := EnsureInstalled(m.BrowserType); installErr == nil {
			browser, err = engine.Launch(m.launchOptions())
		}
		// For Chromium, fall back to any installed Chrome/Edge channel.
		if err != nil && m.BrowserType == "chromium" && m.Channel == "" {
			for _, channel := range []string{"chrome", "msedge"} {
				browser, err = engine.Launch(playwright.BrowserTypeLaunchOptions{
					Headless: playwright.Bool(m.Headless),
					Channel:  playwright.String(channel),
				})
				if err == nil {
					m.Channel = channel
					break
				}
			}
		}
		if err != nil {
			pw.Stop()
			return fmt.Errorf("could not launch %s: %w (hint: run `xsshunts --install-browsers` or set XSSHUNTS_CHANNEL=chrome)", m.BrowserType, err)
		}
	}

	m.pw = pw
	m.browser = browser
	return nil
}

func (m *Manager) engine(pw *playwright.Playwright) (playwright.BrowserType, error) {
	switch m.BrowserType {
	case "chromium":
		return pw.Chromium, nil
	case "webkit":
		return pw.WebKit, nil
	case "firefox":
		return pw.Firefox, nil
	default:
		return nil, fmt.Errorf("unsupported browser engine %q (choose firefox, chromium, or webkit)", m.BrowserType)
	}
}

// launchOptions builds the Playwright launch options (with optional channel).
func (m *Manager) launchOptions() playwright.BrowserTypeLaunchOptions {
	opts := playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(m.Headless),
	}
	if m.Channel != "" {
		opts.Channel = playwright.String(m.Channel)
	}
	return opts
}

// NewContext creates a browser context with the manager's defaults plus extras.
func (m *Manager) NewContext(extraHeaders map[string]string, customUserAgent string) (playwright.BrowserContext, error) {
	if m.browser == nil {
		if err := m.Start(); err != nil {
			return nil, err
		}
	}

	merged := copyStringMap(m.Headers)
	for k, v := range extraHeaders {
		merged[k] = v
	}

	userAgent := customUserAgent
	if userAgent == "" {
		userAgent = config.DefaultUserAgent
	}

	opts := playwright.BrowserNewContextOptions{
		UserAgent:         playwright.String(userAgent),
		IgnoreHttpsErrors: playwright.Bool(true),
	}
	if len(merged) > 0 {
		opts.ExtraHttpHeaders = merged
	}

	ctx, err := m.browser.NewContext(opts)
	if err != nil {
		return nil, err
	}

	if len(m.Cookies) > 0 {
		cookies := make([]playwright.OptionalCookie, 0, len(m.Cookies))
		for _, c := range m.Cookies {
			oc := playwright.OptionalCookie{Name: c.Name, Value: c.Value}
			if c.Domain != "" {
				oc.Domain = playwright.String(c.Domain)
				path := c.Path
				if path == "" {
					path = "/"
				}
				oc.Path = playwright.String(path)
			} else if c.URL != "" {
				oc.URL = playwright.String(c.URL)
			}
			cookies = append(cookies, oc)
		}
		if err := ctx.AddCookies(cookies); err != nil {
			_ = ctx.Close()
			return nil, err
		}
	}
	return ctx, nil
}

// NewSession creates a fresh page (own context) wrapped in a Session.
func (m *Manager) NewSession() (*Session, error) {
	return m.NewSessionWith(nil, "")
}

// NewSessionWith creates a page with extra headers / custom UA.
func (m *Manager) NewSessionWith(extraHeaders map[string]string, customUserAgent string) (*Session, error) {
	ctx, err := m.NewContext(extraHeaders, customUserAgent)
	if err != nil {
		return nil, err
	}
	page, err := ctx.NewPage()
	if err != nil {
		_ = ctx.Close()
		return nil, err
	}
	s := &Session{
		Ctx:       ctx,
		Page:      page,
		TimeoutMS: m.TimeoutMS,
	}
	s.installDialogWatcher()
	return s, nil
}

// Close shuts down the browser and Playwright runtime.
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.browser != nil {
		_ = m.browser.Close()
		m.browser = nil
	}
	if m.pw != nil {
		_ = m.pw.Stop()
		m.pw = nil
	}
}

// Session wraps one page plus dialog/navigation capture state.
type Session struct {
	Ctx       playwright.BrowserContext
	Page      playwright.Page
	TimeoutMS int

	dialogMu      sync.Mutex
	expectedType  string
	expectedValue string
	dialogMatched bool

	responseMu      sync.Mutex
	lastNavResponse playwright.Response
}

func (s *Session) installDialogWatcher() {
	s.Page.OnDialog(func(dialog playwright.Dialog) {
		dType := dialog.Type()
		dMsg := strings.TrimSpace(dialog.Message())

		s.dialogMu.Lock()
		expectedType := strings.ToLower(s.expectedType)
		expectedValue := s.expectedValue
		if expectedType != "" && strings.ToLower(dType) == expectedType && dMsg == expectedValue {
			s.dialogMatched = true
		}
		s.dialogMu.Unlock()

		_ = dialog.Accept()
	})

	s.Page.OnResponse(func(resp playwright.Response) {
		if resp == nil {
			return
		}
		if req := resp.Request(); req != nil && req.IsNavigationRequest() {
			s.responseMu.Lock()
			s.lastNavResponse = resp
			s.responseMu.Unlock()
		}
	})
}

// ExpectDialog sets the signature the next dialog must match.
func (s *Session) ExpectDialog(dialogType string, value int) {
	s.dialogMu.Lock()
	defer s.dialogMu.Unlock()
	s.expectedType = dialogType
	s.expectedValue = fmt.Sprintf("%d", value)
	s.dialogMatched = false
}

// ClearDialog forgets the current dialog expectation.
func (s *Session) ClearDialog() {
	s.dialogMu.Lock()
	defer s.dialogMu.Unlock()
	s.expectedType = ""
	s.expectedValue = ""
	s.dialogMatched = false
}

// DialogMatched reports whether the expected dialog fired.
func (s *Session) DialogMatched() bool {
	s.dialogMu.Lock()
	defer s.dialogMu.Unlock()
	return s.dialogMatched
}

// Goto navigates to a URL with the configured timeout.
func (s *Session) Goto(targetURL string) (playwright.Response, error) {
	return s.Page.Goto(targetURL, playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilStateDomcontentloaded,
		Timeout:   playwright.Float(float64(s.TimeoutMS)),
	})
}

// WaitNetworkIdle waits (best effort) for network idle.
func (s *Session) WaitNetworkIdle(timeoutMS float64) {
	_ = s.Page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State:   playwright.LoadStateNetworkidle,
		Timeout: playwright.Float(timeoutMS),
	})
}

// Content returns the current page HTML.
func (s *Session) Content() (string, error) {
	return s.Page.Content()
}

// OuterHTML returns the live DOM serialization.
func (s *Session) OuterHTML() (string, error) {
	v, err := s.Page.Evaluate("() => document.documentElement.outerHTML")
	if err != nil {
		return "", err
	}
	str, _ := v.(string)
	return str, nil
}

// Eval evaluates JavaScript.
func (s *Session) Eval(expression string, args ...any) (any, error) {
	if len(args) == 0 {
		return s.Page.Evaluate(expression)
	}
	return s.Page.Evaluate(expression, args...)
}

// WaitForTimeout pauses the page for the given milliseconds.
func (s *Session) WaitForTimeout(ms float64) {
	s.Page.WaitForTimeout(ms)
}

// SubmitAndWait triggers a form submission and waits for the resulting navigation.
func (s *Session) SubmitAndWait(js string, arg any) (playwright.Response, error) {
	s.responseMu.Lock()
	s.lastNavResponse = nil
	s.responseMu.Unlock()

	resp, err := s.Page.ExpectNavigation(func() error {
		_, evalErr := s.Page.Evaluate(js, arg)
		return evalErr
	}, playwright.PageExpectNavigationOptions{
		WaitUntil: playwright.WaitUntilStateDomcontentloaded,
		Timeout:   playwright.Float(float64(s.TimeoutMS)),
	})
	if err != nil {
		s.Page.WaitForTimeout(2000)
		s.responseMu.Lock()
		resp = s.lastNavResponse
		s.responseMu.Unlock()
	}
	return resp, err
}

// ResponseSnapshot captures the parts of a response the scanner reports.
type ResponseSnapshot struct {
	Status     int
	StatusText string
	Headers    map[string]string
	Text       string
	URL        string
}

// SnapshotResponse extracts status/headers/body text from a Playwright response.
func SnapshotResponse(resp playwright.Response) ResponseSnapshot {
	out := ResponseSnapshot{Headers: map[string]string{}}
	if resp == nil {
		return out
	}
	out.Status = resp.Status()
	out.StatusText = resp.StatusText()
	out.URL = resp.URL()
	if headers, err := resp.AllHeaders(); err == nil {
		out.Headers = headers
	}
	if body, err := resp.Text(); err == nil {
		out.Text = body
	}
	return out
}

// PageURL returns the current page URL.
func (s *Session) PageURL() string {
	return s.Page.URL()
}

// Close closes the session's page and context.
func (s *Session) Close() {
	if s.Page != nil {
		_ = s.Page.Close()
	}
	if s.Ctx != nil {
		_ = s.Ctx.Close()
	}
}
