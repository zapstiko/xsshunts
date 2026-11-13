package browser

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/playwright-community/playwright-go"
)

// defaultDriverVersion is used only when the expected version cannot be parsed
// from Playwright's own error message.
const defaultDriverVersion = "1.60.0"

var driverVersionRe = regexp.MustCompile(`driver \(v([0-9][0-9.]*)\)`)

var bootstrapClient = &http.Client{Timeout: 5 * time.Minute}

func runOptions(driverDir string) *playwright.RunOptions {
	opts := &playwright.RunOptions{Verbose: false, Stdout: io.Discard}
	if driverDir != "" {
		opts.DriverDirectory = driverDir
	}
	return opts
}

// driverVersionFromError extracts the expected Playwright driver version from
// the "please install the driver (vX.Y.Z)" error.
func driverVersionFromError(err error) string {
	if err != nil {
		if m := driverVersionRe.FindStringSubmatch(err.Error()); len(m) == 2 {
			return m[1]
		}
	}
	return defaultDriverVersion
}

func driverCacheRoot() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "xsshunts", "playwright-driver"), nil
}

func nodeExecutableName() string {
	if runtime.GOOS == "windows" {
		return "node.exe"
	}
	return "node"
}

func driverDirValid(dir string) bool {
	if dir == "" {
		return false
	}
	if _, err := os.Stat(filepath.Join(dir, "package", "cli.js")); err != nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(dir, nodeExecutableName())); err != nil {
		return false
	}
	return true
}

// findCachedDriver returns a previously bootstrapped driver directory.
func findCachedDriver(version string) string {
	root, err := driverCacheRoot()
	if err != nil {
		return ""
	}
	if version != "" {
		if dir := filepath.Join(root, version); driverDirValid(dir) {
			return dir
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(root, entry.Name())
		if driverDirValid(dir) {
			return dir
		}
	}
	return ""
}

// startPlaywright starts Playwright, trying in order: the default driver, a
// previously bootstrapped npm driver, the official driver download, and a
// fresh npm bootstrap. It returns the Playwright instance and the custom
// driver directory (empty when the default driver is used).
func startPlaywright() (*playwright.Playwright, string, error) {
	pw, firstErr := playwright.Run(runOptions(""))
	if firstErr == nil {
		return pw, "", nil
	}

	version := driverVersionFromError(firstErr)

	if dir := findCachedDriver(version); dir != "" {
		if pw, err := playwright.Run(runOptions(dir)); err == nil {
			return pw, dir, nil
		}
	}

	// Official driver-only download (works when the CDN is reachable).
	installOpts := &playwright.RunOptions{
		Verbose:             false,
		Stdout:              io.Discard,
		Stderr:              io.Discard,
		SkipInstallBrowsers: true,
	}
	if err := playwright.Install(installOpts); err == nil {
		if pw, err := playwright.Run(runOptions("")); err == nil {
			return pw, "", nil
		}
	}

	// npm registry fallback: the playwright-core package contains the driver.
	dir, npmErr := bootstrapDriverFromNPM(version)
	if npmErr != nil {
		return nil, "", fmt.Errorf("Playwright driver is unavailable and the npm fallback failed: %w", npmErr)
	}
	pw, err := playwright.Run(runOptions(dir))
	if err != nil {
		return nil, "", fmt.Errorf("bootstrapped Playwright driver could not start: %w", err)
	}
	return pw, dir, nil
}

// installBrowsersWithDriver downloads browser binaries using a resolved driver.
func installBrowsersWithDriver(driverDir string, browsers ...string) error {
	opts := &playwright.RunOptions{
		Verbose:  false,
		Stdout:   io.Discard,
		Stderr:   io.Discard,
		Browsers: browsers,
	}
	if driverDir != "" {
		opts.DriverDirectory = driverDir
	}
	return playwright.Install(opts)
}

// browserInstallTimeout bounds explicit browser downloads so a blocked CDN
// cannot make the installer hang indefinitely.
const browserInstallTimeout = 3 * time.Minute

// InstallBrowsers downloads the requested Playwright browser engines, first
// making the Playwright driver available even when the official CDN is blocked.
func InstallBrowsers(browsers ...string) error {
	pw, driverDir, err := startPlaywright()
	if err != nil {
		return err
	}
	pw.Stop()

	done := make(chan error, 1)
	go func() {
		done <- installBrowsersWithDriver(driverDir, browsers...)
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(browserInstallTimeout):
		return fmt.Errorf("browser download timed out after %s (the Playwright CDN may be blocked)", browserInstallTimeout)
	}
}

// EnsureRuntime makes the Playwright runtime available without downloading
// browser binaries. It returns the custom driver directory when one was
// bootstrapped from npm.
func EnsureRuntime() (string, error) {
	pw, driverDir, err := startPlaywright()
	if err != nil {
		return "", err
	}
	pw.Stop()
	return driverDir, nil
}

// SystemChromePath returns the path of an installed Chromium-based browser,
// or an empty string when none is found. XSSHUNTS_BROWSER_PATH overrides it.
func SystemChromePath() string {
	if explicit := strings.TrimSpace(os.Getenv("XSSHUNTS_BROWSER_PATH")); explicit != "" {
		if _, err := os.Stat(explicit); err == nil {
			return explicit
		}
	}

	var candidates []string
	switch runtime.GOOS {
	case "darwin":
		candidates = []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
			"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
		}
	case "windows":
		candidates = []string{
			`C:\Program Files\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
		}
	default:
		for _, name := range []string{
			"google-chrome", "google-chrome-stable", "chromium",
			"chromium-browser", "microsoft-edge", "brave-browser",
		} {
			if path, err := exec.LookPath(name); err == nil {
				return path
			}
		}
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}

// launchTimeoutMS bounds browser startup. Playwright's 180s default is far too
// long when an engine is broken; a system browser fallback is attempted instead.
func launchTimeoutMS() float64 {
	if raw := strings.TrimSpace(os.Getenv("XSSHUNTS_LAUNCH_TIMEOUT_MS")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 1000 {
			return float64(n)
		}
	}
	if SystemChromePath() != "" {
		return 6000
	}
	return 20000
}

// launchSystemBrowser tries installed Chrome/Edge channels and finally an
// explicit browser path. It returns the launched browser and a description.
func launchSystemBrowser(pw *playwright.Playwright, headless bool) (playwright.Browser, string, error) {
	base := playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(headless),
		Timeout:  playwright.Float(launchTimeoutMS()),
	}

	var lastErr error
	for _, channel := range []string{"chrome", "msedge"} {
		opts := base
		opts.Channel = playwright.String(channel)
		if b, err := pw.Chromium.Launch(opts); err == nil {
			return b, channel, nil
		} else {
			lastErr = err
		}
	}
	if path := SystemChromePath(); path != "" {
		opts := base
		opts.ExecutablePath = playwright.String(path)
		if b, err := pw.Chromium.Launch(opts); err == nil {
			return b, path, nil
		} else {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no installed Chrome, Edge, Chromium or Brave browser was found")
	}
	return nil, "", lastErr
}

// bootstrapDriverFromNPM downloads playwright-core from the npm registry and
// prepares a Playwright driver directory using the system Node.js runtime.
func bootstrapDriverFromNPM(version string) (string, error) {
	if version == "" {
		version = defaultDriverVersion
	}
	root, err := driverCacheRoot()
	if err != nil {
		return "", fmt.Errorf("could not locate cache directory: %w", err)
	}
	target := filepath.Join(root, version)
	if driverDirValid(target) {
		return target, nil
	}

	nodePath, err := exec.LookPath("node")
	if err != nil {
		return "", fmt.Errorf("Node.js is required for the npm driver fallback: %w", err)
	}

	if err := os.MkdirAll(root, 0o755); err != nil {
		return "", fmt.Errorf("could not create driver cache: %w", err)
	}
	tmp, err := os.MkdirTemp(root, version+".tmp-")
	if err != nil {
		return "", fmt.Errorf("could not create temporary driver directory: %w", err)
	}
	success := false
	defer func() {
		if !success {
			_ = os.RemoveAll(tmp)
		}
	}()

	if err := os.MkdirAll(filepath.Join(tmp, "package"), 0o755); err != nil {
		return "", err
	}

	url := fmt.Sprintf("https://registry.npmjs.org/playwright-core/-/playwright-core-%s.tgz", version)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgentForBootstrap())
	resp, err := bootstrapClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("could not download playwright-core from npm: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("npm registry returned HTTP %d for playwright-core@%s", resp.StatusCode, version)
	}

	if err := extractDriverTarball(resp.Body, tmp); err != nil {
		return "", fmt.Errorf("could not extract playwright-core: %w", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "package", "cli.js")); err != nil {
		return "", fmt.Errorf("downloaded playwright-core package is invalid: %w", err)
	}
	if err := installNodeRuntime(tmp, nodePath); err != nil {
		return "", fmt.Errorf("could not prepare Node.js runtime: %w", err)
	}

	_ = os.RemoveAll(target)
	if err := os.Rename(tmp, target); err != nil {
		return "", fmt.Errorf("could not store bootstrapped driver: %w", err)
	}
	success = true
	return target, nil
}

func userAgentForBootstrap() string {
	return "xsshunts-bootstrap"
}

// extractDriverTarball extracts the package/ prefix of an npm tarball into dest.
func extractDriverTarball(r io.Reader, dest string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		name := strings.TrimPrefix(hdr.Name, "package/")
		if name == "" || name == hdr.Name {
			continue
		}
		clean := filepath.Clean(name)
		if clean == "." || strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
			continue
		}
		target := filepath.Join(dest, "package", clean)

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			file, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
			if err != nil {
				return err
			}
			if _, err := io.Copy(file, tr); err != nil {
				file.Close()
				return err
			}
			if err := file.Close(); err != nil {
				return err
			}
		}
	}
	return nil
}

func installNodeRuntime(dir, nodePath string) error {
	target := filepath.Join(dir, nodeExecutableName())
	_ = os.Remove(target)
	if runtime.GOOS != "windows" {
		if err := os.Symlink(nodePath, target); err == nil {
			return nil
		}
	}
	return copyExecutable(nodePath, target)
}

func copyExecutable(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}
