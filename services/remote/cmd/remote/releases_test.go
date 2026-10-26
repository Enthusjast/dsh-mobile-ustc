package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAppReleasesRequireAnExplicitProtectedValidCatalog(t *testing.T) {
	if catalog, err := loadAppReleases(""); err != nil || catalog != nil {
		t.Fatal("release publication enabled without configuration", err)
	}
	_, source, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(source), "../../../../deploy/android/releases.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "releases.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if catalog, err := loadAppReleases(path); err != nil || catalog == nil {
		t.Fatal("protected release catalog failed", err)
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAppReleases(path); err == nil {
		t.Fatal("mutable public deployment policy accepted")
	}
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{`{}`, `{"secret":"PRIVATE_RELEASE_CONFIGURATION"}`, string(raw) + "{}"} {
		if err = os.WriteFile(path, []byte(invalid), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadAppReleases(path); err == nil || strings.Contains(err.Error(), "PRIVATE_RELEASE_CONFIGURATION") {
			t.Fatal("invalid catalog accepted or disclosed")
		}
	}
	link := filepath.Join(t.TempDir(), "releases.json")
	if err = os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAppReleases(link); err == nil {
		t.Fatal("release policy symlink accepted")
	}
}
