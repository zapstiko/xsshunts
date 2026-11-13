// Package updater implements checking for and installing the latest GitHub
// release of xsshunts. Downloads are verified against the release's
// SHA256SUMS asset before the running executable is replaced.
package updater

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// RepoSlug is the GitHub repository that publishes xsshunts releases.
const RepoSlug = "zapstiko/xsshunts"

var (
	apiBase        = "https://api.github.com"
	apiClient      = &http.Client{Timeout: 10 * time.Second}
	downloadClient = &http.Client{Timeout: 5 * time.Minute}
	userAgent      = "xsshunts-updater"
)

// Asset is one downloadable file attached to a release.
type Asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

// Release is the subset of the GitHub release API used by the updater.
type Release struct {
	TagName string  `json:"tag_name"`
	Name    string  `json:"name"`
	HTMLURL string  `json:"html_url"`
	Assets  []Asset `json:"assets"`
}

// FetchLatest returns the latest published (non-draft, non-prerelease) release.
func FetchLatest() (*Release, error) {
	url := strings.TrimRight(apiBase, "/") + "/repos/" + RepoSlug + "/releases/latest"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := apiClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not reach GitHub: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("GitHub API returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var release Release
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&release); err != nil {
		return nil, fmt.Errorf("invalid GitHub release response: %w", err)
	}
	if release.TagName == "" {
		return nil, fmt.Errorf("GitHub release has no tag name")
	}
	return &release, nil
}

// parseVersion parses "1.2.3", "v1.2.3" or "1.2.3-beta" into numeric parts.
func parseVersion(v string) ([3]int, bool) {
	var out [3]int
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(strings.TrimPrefix(v, "v"), "V")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return out, false
	}
	for i := 0; i < 3 && i < len(parts); i++ {
		n, err := strconv.Atoi(strings.TrimSpace(parts[i]))
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// IsNewer reports whether latest is a newer semantic version than current.
func IsNewer(current, latest string) bool {
	cur, okCur := parseVersion(current)
	newer, okLatest := parseVersion(latest)
	if !okCur || !okLatest {
		return false
	}
	for i := 0; i < 3; i++ {
		if newer[i] != cur[i] {
			return newer[i] > cur[i]
		}
	}
	return false
}

// NormalizeVersion strips a leading v/V and surrounding whitespace.
func NormalizeVersion(v string) string {
	return strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(v), "v"), "V")
}

// AssetName returns the expected release asset name for a platform.
func AssetName(version, goos, goarch string) string {
	name := fmt.Sprintf("xsshunts_%s_%s_%s", NormalizeVersion(version), goos, goarch)
	if goos == "windows" {
		name += ".exe"
	}
	return name
}

// FindAsset locates the release asset for the given platform. It prefers the
// exact versioned name and falls back to any xsshunts_* asset for the platform.
func FindAsset(rel *Release, goos, goarch string) *Asset {
	if rel == nil {
		return nil
	}
	want := strings.ToLower(AssetName(rel.TagName, goos, goarch))
	for i := range rel.Assets {
		if strings.ToLower(rel.Assets[i].Name) == want {
			return &rel.Assets[i]
		}
	}

	suffix := "_" + strings.ToLower(goos) + "_" + strings.ToLower(goarch)
	if goos == "windows" {
		suffix += ".exe"
	}
	for i := range rel.Assets {
		name := strings.ToLower(rel.Assets[i].Name)
		if strings.HasPrefix(name, "xsshunts_") && strings.HasSuffix(name, suffix) {
			return &rel.Assets[i]
		}
	}
	return nil
}

// checksumAsset returns the release's SHA256SUMS asset, if present.
func checksumAsset(rel *Release) *Asset {
	if rel == nil {
		return nil
	}
	for i := range rel.Assets {
		if strings.EqualFold(rel.Assets[i].Name, "SHA256SUMS") {
			return &rel.Assets[i]
		}
	}
	for i := range rel.Assets {
		name := strings.ToLower(rel.Assets[i].Name)
		if strings.Contains(name, "sha256") && strings.Contains(name, "sum") {
			return &rel.Assets[i]
		}
	}
	return nil
}

// ChecksumFor extracts the expected SHA-256 for an asset from a sums file.
func ChecksumFor(sumsText, assetName string) (string, bool) {
	for _, line := range strings.Split(sumsText, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimPrefix(fields[1], "*")
		if strings.TrimSpace(name) == assetName {
			sum := strings.ToLower(fields[0])
			if len(sum) == 64 {
				return sum, true
			}
		}
	}
	return "", false
}

func fetchText(client *http.Client, url string, maxBytes int64) (string, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download returned HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// DownloadWithChecksum downloads the asset into dir, verifies it against the
// release's SHA256SUMS asset, and returns the path of the verified temp file.
// Automatic updates are refused when no checksum asset is published.
func DownloadWithChecksum(rel *Release, asset *Asset, dir string) (string, error) {
	if rel == nil || asset == nil {
		return "", fmt.Errorf("no download asset selected")
	}
	sums := checksumAsset(rel)
	if sums == nil {
		return "", fmt.Errorf("release %s does not publish SHA256SUMS; refusing automatic update", rel.TagName)
	}
	sumsText, err := fetchText(downloadClient, sums.BrowserDownloadURL, 1<<20)
	if err != nil {
		return "", fmt.Errorf("could not fetch SHA256SUMS: %w", err)
	}
	expected, ok := ChecksumFor(sumsText, asset.Name)
	if !ok {
		return "", fmt.Errorf("asset %s is missing from SHA256SUMS", asset.Name)
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("could not prepare download directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".xsshunts-update-*")
	if err != nil {
		return "", fmt.Errorf("could not create temporary file: %w", err)
	}
	tmpName := tmp.Name()
	success := false
	defer func() {
		tmp.Close()
		if !success {
			_ = os.Remove(tmpName)
		}
	}()

	req, err := http.NewRequest(http.MethodGet, asset.BrowserDownloadURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := downloadClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download returned HTTP %d", resp.StatusCode)
	}

	hasher := sha256.New()
	written, err := io.Copy(io.MultiWriter(tmp, hasher), resp.Body)
	if err != nil {
		return "", fmt.Errorf("download interrupted: %w", err)
	}
	if asset.Size > 0 && written != asset.Size {
		return "", fmt.Errorf("download truncated: got %d of %d bytes", written, asset.Size)
	}
	if err := tmp.Sync(); err != nil {
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}

	actual := hex.EncodeToString(hasher.Sum(nil))
	if !strings.EqualFold(actual, expected) {
		return "", fmt.Errorf("checksum mismatch for %s (expected %s, got %s)", asset.Name, expected, actual)
	}
	if err := os.Chmod(tmpName, 0o755); err != nil {
		return "", err
	}
	success = true
	return tmpName, nil
}

// ReplaceResult describes the outcome of replacing the running executable.
type ReplaceResult struct {
	Path   string
	Manual bool // true on Windows, where a running executable cannot be replaced
}

// ReplaceExecutable atomically swaps the running binary with newPath.
func ReplaceExecutable(newPath string) (*ReplaceResult, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("could not locate current executable: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}

	if runtime.GOOS == "windows" {
		target := filepath.Join(filepath.Dir(exe), "xsshunts-new.exe")
		_ = os.Remove(target)
		if err := os.Rename(newPath, target); err != nil {
			if err := copyFile(newPath, target); err != nil {
				return nil, fmt.Errorf("could not save new executable: %w", err)
			}
			_ = os.Remove(newPath)
		}
		return &ReplaceResult{Path: target, Manual: true}, nil
	}

	if err := os.Chmod(newPath, 0o755); err != nil {
		return nil, fmt.Errorf("could not set executable permissions: %w", err)
	}
	if err := os.Rename(newPath, exe); err != nil {
		return nil, fmt.Errorf("could not replace %s: %w", exe, err)
	}
	return &ReplaceResult{Path: exe}, nil
}

func copyFile(src, dst string) error {
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
