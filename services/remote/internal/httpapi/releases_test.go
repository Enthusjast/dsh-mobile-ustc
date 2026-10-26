package httpapi

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"dsh-mobile-ustc/services/remote/internal/releases"
)

func releaseCatalog(t *testing.T) *releases.Catalog {
	t.Helper()
	_, source, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(source), "../../../../deploy/android/releases.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := releases.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}

func TestAppReleaseRouteIsAbsentWithoutConfiguration(t *testing.T) {
	repository := &fakeRepository{}
	response := httptest.NewRecorder()
	New(repository, nil).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/app/releases/latest", nil))
	if response.Code != http.StatusNotFound || repository.activeDeviceCall != 0 || repository.releaseCalls != 0 {
		t.Fatal("disabled release endpoint required credentials or exposed metadata", response.Code)
	}
}
