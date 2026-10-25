package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dsh-mobile-ustc/services/remote/internal/store"
)

const filePolicyFixture = "LocalSocket /run/clamav/clamd.sock\nStreamMaxLength 200M\nMaxFileSize 200M\nMaxScanSize 400M\nAlertExceedsMax yes\nScanArchive yes\nMaxRecursion 16\nMaxFiles 10000\nMaxScanTime 600000\n"

func fileDeploymentFixture(t *testing.T) (string, fileDeployment) {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "files.json")
	if err := os.WriteFile(filepath.Join(directory, "keys.json"), []byte(`{"access_key_id":"fixture-access","secret_access_key":"PRIVATE_STORAGE_SECRET"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "clamd.conf"), []byte(filePolicyFixture), 0600); err != nil {
		t.Fatal(err)
	}
	var config fileDeployment
	config.Storage.Endpoint = "https://objects.example.edu"
	config.Storage.Region = "fixture-1"
	config.Storage.Bucket = "remote-files"
	config.Storage.KMSKeyID = "explicit-kms-key"
	config.Storage.CredentialsFile = "keys.json"
	config.Scanner.Network = "unix"
	config.Scanner.Address = "/run/clamav/clamd.sock"
	config.Scanner.PolicyFile = "clamd.conf"
	config.Scanner.TimeoutSeconds = 60
	config.Limits.OrganizationBytes = 1_000_000_000
	config.Limits.UserBytes = 500_000_000
	config.Limits.SessionBytes = 200_000_000
	config.Limits.OrganizationFiles = 1000
	config.Limits.UserFiles = 100
	config.Limits.SessionFiles = 10
	config.Limits.UploadURLSeconds = 300
	config.Limits.AbandonSeconds = 3600
	config.Limits.RetainSeconds = 86400
	config.Workers = 2
	config.TaskTimeoutSeconds = 60
	return path, config
}
func writeFileDeployment(t *testing.T, path string, config fileDeployment) {
	t.Helper()
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestFileDeploymentIsExplicitOptionalProtectedAndNotReadyWithoutEngineProbe(t *testing.T) {
	if runtime, err := loadFileRuntime("", nil); err != nil || runtime != nil {
		t.Fatal("optional files were implicitly enabled")
	}
	path, config := fileDeploymentFixture(t)
	writeFileDeployment(t, path, config)
	runtime, err := loadFileRuntime(path, &store.Postgres{DB: &sql.DB{}})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	if runtime.service.Ready() {
		t.Fatal("configuration alone passed the scanner probe")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadFileRuntime(path, &store.Postgres{DB: &sql.DB{}}); !errors.Is(err, errFileConfiguration) {
		t.Fatal("public configuration accepted")
	}
}

func TestFileDeploymentRejectsUnsafePolicyAndCredentialsWithoutPrintingSecrets(t *testing.T) {
	for _, scenario := range []string{"missing-kms", "http", "public-key-file", "symlink", "unsafe-policy", "unknown-json", "overflow", "workers"} {
		t.Run(scenario, func(t *testing.T) {
			path, config := fileDeploymentFixture(t)
			switch scenario {
			case "missing-kms":
				config.Storage.KMSKeyID = ""
			case "http":
				config.Storage.Endpoint = "http://127.0.0.1:9000"
			case "public-key-file":
				if err := os.Chmod(filepath.Join(filepath.Dir(path), "keys.json"), 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				config.Storage.CredentialsFile = "key-link.json"
				if err := os.Symlink("keys.json", filepath.Join(filepath.Dir(path), config.Storage.CredentialsFile)); err != nil {
					t.Fatal(err)
				}
			case "unsafe-policy":
				if err := os.WriteFile(filepath.Join(filepath.Dir(path), "clamd.conf"), []byte(strings.Replace(filePolicyFixture, "AlertExceedsMax yes", "AlertExceedsMax no", 1)), 0600); err != nil {
					t.Fatal(err)
				}
			case "overflow":
				config.TaskTimeoutSeconds = 1 << 62
			case "workers":
				config.Workers = 100
			}
			writeFileDeployment(t, path, config)
			if scenario == "unknown-json" {
				raw, _ := os.ReadFile(path)
				raw = append([]byte(`{"unexpected":true,`), raw[1:]...)
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			_, err := loadFileRuntime(path, &store.Postgres{DB: &sql.DB{}})
			if !errors.Is(err, errFileConfiguration) || strings.Contains(err.Error(), "PRIVATE_STORAGE_SECRET") {
				t.Fatalf("unsafe configuration error=%v", err)
			}
		})
	}
}

func TestFileScannerPolicyRequiresRealBoundsAndRejectsIncludesAndAmbiguity(t *testing.T) {
	for _, scenario := range []string{"small-stream", "small-file", "small-scan", "missing-maxfiles", "duplicate", "include", "unlimited"} {
		t.Run(scenario, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "clamd.conf")
			body := filePolicyFixture
			switch scenario {
			case "small-stream":
				body = strings.Replace(body, "StreamMaxLength 200M", "StreamMaxLength 1M", 1)
			case "small-file":
				body = strings.Replace(body, "MaxFileSize 200M", "MaxFileSize 1M", 1)
			case "small-scan":
				body = strings.Replace(body, "MaxScanSize 400M", "MaxScanSize 1M", 1)
			case "missing-maxfiles":
				body = strings.Replace(body, "MaxFiles 10000\n", "", 1)
			case "duplicate":
				body += "AlertExceedsMax no\n"
			case "include":
				body += "Include /etc/clamav/override.conf\n"
			case "unlimited":
				body = strings.Replace(body, "MaxScanTime 600000", "MaxScanTime 0", 1)
			}
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := fileScannerPolicy(path); !errors.Is(err, errFileConfiguration) {
				t.Fatal("unsafe scanning policy accepted")
			}
		})
	}
}
