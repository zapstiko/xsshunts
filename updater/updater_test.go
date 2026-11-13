package updater

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsNewer(t *testing.T) {
	cases := []struct {
		current, latest string
		want            bool
	}{
		{"1.0.0", "v1.0.0", false},
		{"1.0.0", "v1.0.1", true},
		{"1.0.0", "v1.1.0", true},
		{"1.0.9", "v1.1.0", true},
		{"1.2.3", "v1.2.2", false},
		{"v2.0.0", "2.1.0-beta", true},
		{"1.0", "v1.0.1", true},
		{"bad", "v9.9.9", false},
	}
	for _, tc := range cases {
		if got := IsNewer(tc.current, tc.latest); got != tc.want {
			t.Errorf("IsNewer(%q, %q) = %v, want %v", tc.current, tc.latest, got, tc.want)
		}
	}
}

func TestAssetName(t *testing.T) {
	cases := []struct {
		version, goos, goarch, want string
	}{
		{"v1.1.0", "darwin", "arm64", "xsshunts_1.1.0_darwin_arm64"},
		{"1.1.0", "linux", "amd64", "xsshunts_1.1.0_linux_amd64"},
		{"v1.1.0", "windows", "amd64", "xsshunts_1.1.0_windows_amd64.exe"},
	}
	for _, tc := range cases {
		if got := AssetName(tc.version, tc.goos, tc.goarch); got != tc.want {
			t.Errorf("AssetName(%q,%q,%q) = %q, want %q", tc.version, tc.goos, tc.goarch, got, tc.want)
		}
	}
}

func TestFindAsset(t *testing.T) {
	rel := &Release{TagName: "v1.1.0", Assets: []Asset{
		{Name: "SHA256SUMS"},
		{Name: "xsshunts_1.1.0_linux_amd64"},
		{Name: "xsshunts_1.1.0_windows_amd64.exe"},
	}}
	if a := FindAsset(rel, "linux", "amd64"); a == nil || a.Name != "xsshunts_1.1.0_linux_amd64" {
		t.Fatalf("exact linux asset not found: %+v", a)
	}
	if a := FindAsset(rel, "windows", "amd64"); a == nil || !strings.HasSuffix(a.Name, ".exe") {
		t.Fatalf("windows asset not found: %+v", a)
	}
	if a := FindAsset(rel, "darwin", "arm64"); a != nil {
		t.Fatalf("unexpected asset for unsupported platform: %+v", a)
	}

	// Fallback to suffix matching when the version embedded in the asset name differs.
	rel.Assets = append(rel.Assets, Asset{Name: "xsshunts_0.9.0_linux_amd64"})
	if a := FindAsset(rel, "linux", "amd64"); a == nil || a.Name != "xsshunts_1.1.0_linux_amd64" {
		t.Fatalf("preferred asset was not selected: %+v", a)
	}
}

func TestChecksumFor(t *testing.T) {
	sums := "abc123\n" +
		strings.Repeat("a", 64) + "  xsshunts_1.1.0_linux_amd64\n" +
		strings.Repeat("b", 64) + " *xsshunts_1.1.0_windows_amd64.exe\n"
	if got, ok := ChecksumFor(sums, "xsshunts_1.1.0_linux_amd64"); !ok || got != strings.Repeat("a", 64) {
		t.Fatalf("checksum lookup failed: %q %v", got, ok)
	}
	if got, ok := ChecksumFor(sums, "xsshunts_1.1.0_windows_amd64.exe"); !ok || got != strings.Repeat("b", 64) {
		t.Fatalf("binary-mode checksum lookup failed: %q %v", got, ok)
	}
	if _, ok := ChecksumFor(sums, "missing"); ok {
		t.Fatal("expected checksum lookup to fail for missing asset")
	}
}

func TestFetchLatest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/"+RepoSlug+"/releases/latest" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"tag_name": "v9.9.9",
			"name":     "Test release",
			"html_url": "https://example.test/release",
			"assets": []map[string]interface{}{
				{"name": "xsshunts_9.9.9_linux_amd64", "browser_download_url": "https://example.test/bin", "size": 42},
			},
		})
	}))
	defer srv.Close()

	oldBase, oldClient := apiBase, apiClient
	apiBase, apiClient = srv.URL, srv.Client()
	defer func() { apiBase, apiClient = oldBase, oldClient }()

	rel, err := FetchLatest()
	if err != nil {
		t.Fatalf("FetchLatest: %v", err)
	}
	if rel.TagName != "v9.9.9" || len(rel.Assets) != 1 {
		t.Fatalf("unexpected release: %+v", rel)
	}
}

func TestDownloadWithChecksum(t *testing.T) {
	payload := []byte("verified-binary-content")
	sum := sha256.Sum256(payload)
	sums := hex.EncodeToString(sum[:]) + "  xsshunts_9.9.9_darwin_arm64\n"

	mux := http.NewServeMux()
	mux.HandleFunc("/asset", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(payload) })
	mux.HandleFunc("/SHA256SUMS", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(sums)) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	oldClient := downloadClient
	downloadClient = srv.Client()
	defer func() { downloadClient = oldClient }()

	rel := &Release{TagName: "v9.9.9", Assets: []Asset{
		{Name: "xsshunts_9.9.9_darwin_arm64", BrowserDownloadURL: srv.URL + "/asset", Size: int64(len(payload))},
		{Name: "SHA256SUMS", BrowserDownloadURL: srv.URL + "/SHA256SUMS"},
	}}
	dir := t.TempDir()
	path, err := DownloadWithChecksum(rel, &rel.Assets[0], dir)
	if err != nil {
		t.Fatalf("DownloadWithChecksum: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if string(data) != string(payload) {
		t.Fatalf("downloaded content mismatch: %q", data)
	}
	if info, err := os.Stat(path); err != nil || info.Mode()&0o111 == 0 {
		t.Fatalf("downloaded file is not executable: %v %v", info, err)
	}
	if filepath.Dir(path) != dir {
		t.Fatalf("download placed outside target dir: %s", path)
	}
}

func TestDownloadChecksumMismatch(t *testing.T) {
	payload := []byte("tampered")
	mux := http.NewServeMux()
	mux.HandleFunc("/asset", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(payload) })
	mux.HandleFunc("/SHA256SUMS", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("0", 64) + "  xsshunts_9.9.9_darwin_arm64\n"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	oldClient := downloadClient
	downloadClient = srv.Client()
	defer func() { downloadClient = oldClient }()

	rel := &Release{TagName: "v9.9.9", Assets: []Asset{
		{Name: "xsshunts_9.9.9_darwin_arm64", BrowserDownloadURL: srv.URL + "/asset"},
		{Name: "SHA256SUMS", BrowserDownloadURL: srv.URL + "/SHA256SUMS"},
	}}
	if _, err := DownloadWithChecksum(rel, &rel.Assets[0], t.TempDir()); err == nil {
		t.Fatal("expected checksum mismatch error")
	}
}

func TestDownloadRequiresChecksums(t *testing.T) {
	rel := &Release{TagName: "v9.9.9", Assets: []Asset{
		{Name: "xsshunts_9.9.9_linux_amd64", BrowserDownloadURL: "https://example.test/bin"},
	}}
	if _, err := DownloadWithChecksum(rel, &rel.Assets[0], t.TempDir()); err == nil {
		t.Fatal("expected refusal when SHA256SUMS is absent")
	}
}
