// Package browser drives a real Chromium instance (chromedp) to confirm XSS
// payloads. Every probe runs in a short-lived tab that listens for
// JavaScript dialogs (alert/confirm/prompt). When the payload's canary value
// reaches an intercepted dialog, the XSS is confirmed with zero false
// positives.
package browser

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
)

// DialogHit describes an intercepted JavaScript dialog.
type DialogHit struct {
	Type    string
	Message string
	URL     string
}

// ProbeResult is the outcome of a browser infiltration.
type ProbeResult struct {
	Dialog *DialogHit
	HTML   string
}

// ProbeOptions configures a single tab probe.
type ProbeOptions struct {
	URL         string
	Timeout     time.Duration
	Settle      time.Duration // extra wait after navigation for dialogs
	Headers     map[string]string
	Cookies     map[string]string
	AfterLoadJS string
	CaptureHTML bool
}

// Manager owns the chromium process.
type Manager struct {
	root    context.Context
	rootFn  context.CancelFunc
	browser context.Context
}

func detectPath(explicit string) (string, error) {
	var candidates []string
	switch runtime.GOOS {
	case "darwin":
		candidates = []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
			"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
			"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
			"google-chrome", "chromium", "chrome", "msedge", "brave",
		}
	case "windows":
		candidates = []string{
			`C:\Program Files\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
		}
	default:
		candidates = []string{
			"/usr/bin/google-chrome", "/usr/bin/google-chrome-stable", "/usr/bin/chromium", "/usr/bin/chromium-browser", "/snap/bin/chromium", "/usr/bin/brave-browser", "/usr/bin/microsoft-edge",
			"google-chrome", "chromium", "chromium-browser", "chrome",
		}
	}
	if explicit != "" {
		candidates = append([]string{explicit}, candidates...)
	}
	for _, path := range candidates {
		if strings.ContainsRune(path, os.PathSeparator) || strings.HasPrefix(path, "/") {
			if st, err := os.Stat(path); err == nil && !st.IsDir() {
				return path, nil
			}
			continue
		}
		if p, err := exec.LookPath(path); err == nil {
			return p, nil
		}
	}
	if env := os.Getenv("BROWSER_PATH"); env != "" {
		if p, err := exec.LookPath(env); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("no chromium-based browser found (install Google Chrome or pass --browser-path)")
}

// New starts the chromium process under the given options.
func New(explicitPath string, kind string, headless bool) (*Manager, error) {
	path, err := detectPath(explicitPath)
	if err != nil {
		return nil, err
	}
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(path),
		chromedp.Flag("headless", headless),
		chromedp.Flag("window-size", "1440,900"),
	)
	if headless {
		opts = append(opts,
			chromedp.Flag("disable-gpu", true),
			chromedp.Flag("mute-audio", true),
		)
	}
	root, rootCancel := context.WithCancel(context.Background())
	allocCtx, _ := chromedp.NewExecAllocator(root, opts...)
	bctx, _ := chromedp.NewContext(allocCtx)
	checkCtx, checkCancel := context.WithTimeout(bctx, 30*time.Second)
	defer checkCancel()
	if _, err := chromedp.Run(checkCtx, chromedp.Navigate("about:blank")); err != nil {
		rootCancel()
		return nil, fmt.Errorf("starting %s at %s: %w", kind, path, err)
	}
	return &Manager{root: root, rootFn: rootCancel, browser: bctx}, nil
}

// Close terminates the browser process.
func (m *Manager) Close() {
	if m != nil && m.rootFn != nil {
		m.rootFn()
	}
}

// Probe opens a fresh tab, installs the dialog watcher, applies per-session
// headers/cookies, navigates and waits for a dialog or the settle window.
func (m *Manager) Probe(o ProbeOptions) (*ProbeResult, error) {
	if m == nil {
		return nil, fmt.Errorf("browser manager not initialized")
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	settle := o.Settle
	if settle <= 0 {
		settle = 1800 * time.Millisecond
	}

	tabCtx, tabCancel := chromedp.NewContext(m.browser)
	defer tabCancel()
	tabCtx, cancelDeadline := context.WithTimeout(tabCtx, timeout)
	defer cancelDeadline()

	// dialog watcher: captures alert/confirm/prompt messages.
	seen := make(chan *DialogHit, 16)
	dialogs := chromedp.Events(tabCtx, page.JavascriptDialogOpening)
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		for ev, err := range dialogs {
			if err != nil {
				return
			}
			seen <- &DialogHit{Type: string(ev.Type), Message: ev.Message, URL: ev.URL}
			// dismiss so the page does not stall; errors are non fatal
			go func() {
				dctx, dcancel := context.WithTimeout(tabCtx, 3*time.Second)
				defer dcancel()
				_, _ = chromedp.Call(dctx, page.HandleJavaScriptDialog, page.HandleJavaScriptDialogParams{Accept: false})
			}()
		}
	}()

	steps := []chromedp.Action[chromedp.Void]{}
	if len(o.Cookies) > 0 {
		if u, perr := url.Parse(o.URL); perr == nil && u.Host != "" {
			base := u.Scheme + "://" + u.Host
			for name, val := range o.Cookies {
				_, err := chromedp.Call(tabCtx, network.SetCookie, network.SetCookieParams{Name: name, Value: val, URL: base, Path: "/"})
				if err != nil {
					return nil, fmt.Errorf("set cookie %s: %w", name, err)
				}
			}
		}
	}
	if len(o.Headers) > 0 {
		hdrs := network.Headers{}
		for k, v := range o.Headers {
			hdrs[k] = v
		}
		if _, err := chromedp.Call(tabCtx, network.SetExtraHTTPHeaders, network.SetExtraHTTPHeadersParams{Headers: hdrs}); err != nil {
			return nil, fmt.Errorf("set extra headers: %w", err)
		}
	}
	steps = append(steps, chromedp.Navigate(o.URL))
	if err := chromedp.Do(tabCtx, steps...); err != nil && tabCtx.Err() == nil {
		return nil, err
	}
	if o.AfterLoadJS != "" {
		ectx, ecancel := context.WithTimeout(tabCtx, 5*time.Second)
		_, _ = chromedp.Run(ectx, chromedp.Evaluate[string](o.AfterLoadJS))
		ecancel()
	}
	// wait for dialog / settle window
	select {
	case hit := <-seen:
		html := ""
		if o.CaptureHTML && tabCtx.Err() == nil {
			hctx, hcancel := context.WithTimeout(tabCtx, 2*time.Second)
			html, _ = chromedp.Run(hctx, chromedp.OuterHTML(chromedp.CSS("html")))
			hcancel()
		}
		return &ProbeResult{Dialog: hit, HTML: html}, nil
	case <-time.After(settle):
	case <-tabCtx.Done():
	}
	html := ""
	if o.CaptureHTML && tabCtx.Err() == nil {
		hctx, hcancel := context.WithTimeout(tabCtx, 2*time.Second)
		html, _ = chromedp.Run(hctx, chromedp.OuterHTML(chromedp.CSS("html")))
		hcancel()
	}
	return &ProbeResult{Dialog: nil, HTML: html}, nil
}
