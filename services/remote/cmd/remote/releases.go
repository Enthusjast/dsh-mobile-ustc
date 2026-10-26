package main

import (
	"errors"

	"dsh-mobile-ustc/services/remote/internal/releases"
)

var errReleaseConfiguration = errors.New("remote service protected APK release configuration is invalid")

func loadAppReleases(path string) (*releases.Catalog, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := readProtectedFile(path, 128<<10)
	if err != nil {
		return nil, errReleaseConfiguration
	}
	defer clear(raw)
	catalog, err := releases.Parse(raw)
	if err != nil {
		return nil, errReleaseConfiguration
	}
	return catalog, nil
}
