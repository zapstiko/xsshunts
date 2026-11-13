package browser

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDriverVersionFromError(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{errors.New("please install the driver (v1.60.0) first"), "1.60.0"},
		{errors.New("driver exists but version not 1.61.1 in : /tmp/driver"), "1.60.0"},
		{errors.New("some other failure"), defaultDriverVersion},
		{nil, defaultDriverVersion},
	}
	for _, tc := range cases {
		if got := driverVersionFromError(tc.err); got != tc.want {
			t.Errorf("driverVersionFromError(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

func TestExtractDriverTarball(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	add := func(name, content string, mode int64) {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: mode, Size: int64(len(content)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	add("package/cli.js", "console.log('driver')", 0o644)
	add("package/lib/index.js", "module.exports = {}", 0o644)
	add("package/../evil.txt", "escape", 0o644)
	add("README.md", "not part of package", 0o644)

	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	dest := t.TempDir()
	if err := extractDriverTarball(bytes.NewReader(buf.Bytes()), dest); err != nil {
		t.Fatalf("extractDriverTarball: %v", err)
	}

	cli, err := os.ReadFile(filepath.Join(dest, "package", "cli.js"))
	if err != nil || string(cli) != "console.log('driver')" {
		t.Fatalf("cli.js missing or wrong: %q %v", cli, err)
	}
	if _, err := os.Stat(filepath.Join(dest, "package", "lib", "index.js")); err != nil {
		t.Fatalf("nested file missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "evil.txt")); err == nil {
		t.Fatal("path traversal entry was extracted")
	}
	if _, err := os.Stat(filepath.Join(dest, "package", "README.md")); err == nil {
		t.Fatal("non-package entry was extracted")
	}
}

func TestDriverDirValid(t *testing.T) {
	dir := t.TempDir()
	if driverDirValid(dir) {
		t.Fatal("empty dir must not be a valid driver")
	}
	if err := os.MkdirAll(filepath.Join(dir, "package"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package", "cli.js"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, nodeExecutableName()), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !driverDirValid(dir) {
		t.Fatal("driver dir with cli.js and node should be valid")
	}
}
