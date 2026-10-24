package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/store"
)

func deploymentFixture(t *testing.T) (string, approvalDeployment) {
	t.Helper()
	root := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	var config approvalDeployment
	config.Policy.Version, config.Policy.Profile = 7, "school/step-up"
	age := int64(60)
	config.Policy.MaxAge = &age
	config.Mappings = []auth.AssuranceMapping{{Issuer: "https://id.example.edu", ClientID: "android", Profile: "school/step-up", ACR: "school:2", RequiredAMR: []string{"otp"}}}
	config.Signing.Issuer, config.Signing.KeyID, config.Signing.PrivateFile = "https://remote.example.edu", "dsh-approval-authority/test", "key.pem"
	config.Signing.ValidFrom = time.Now().Add(-time.Hour).UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
	config.Signing.ValidUntil = time.Now().Add(time.Hour).UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
	return filepath.Join(root, "approvals.json"), config
}

func TestApprovalDeploymentIsDisabledUnlessExplicitlyConfigured(t *testing.T) {
	database := &store.Postgres{DB: &sql.DB{}}
	if config, err := loadApprovalConfig("", database, "https://id.example.edu", []string{"android"}); err != nil || config != nil {
		t.Fatal("unconfigured approvals enabled")
	}
	path, config := deploymentFixture(t)
	raw, _ := json.Marshal(config)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadApprovalConfig(path, database, "https://id.example.edu", []string{"android"})
	if err != nil || loaded == nil || loaded.Control == nil || loaded.Leases == nil {
		t.Fatalf("explicit deployment failed: %v", err)
	}
}

func TestApprovalDeploymentRejectsUnverifiedMappingsAndMissingEvidence(t *testing.T) {
	path, config := deploymentFixture(t)
	for _, variant := range []struct {
		name   string
		mutate func(*approvalDeployment)
	}{
		{"missing age", func(c *approvalDeployment) { c.Policy.MaxAge = nil }},
		{"unknown profile", func(c *approvalDeployment) { c.Policy.Profile = "unmapped" }},
		{"missing mappings", func(c *approvalDeployment) { c.Mappings = nil }},
		{"other issuer", func(c *approvalDeployment) { c.Mappings[0].Issuer = "https://attacker.example" }},
		{"other client", func(c *approvalDeployment) { c.Mappings[0].ClientID = "unregistered" }},
		{"missing acr", func(c *approvalDeployment) { c.Mappings[0].ACR = "" }},
		{"duplicate methods", func(c *approvalDeployment) { c.Mappings[0].RequiredAMR = []string{"otp", "otp"} }},
		{"untrusted signer issuer", func(c *approvalDeployment) { c.Signing.Issuer = "http://remote.example.edu" }},
		{"future key", func(c *approvalDeployment) {
			c.Signing.ValidFrom = time.Now().Add(time.Hour).UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
		}},
		{"expired key", func(c *approvalDeployment) {
			c.Signing.ValidUntil = time.Now().Add(-time.Minute).UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
		}},
		{"missing key", func(c *approvalDeployment) { c.Signing.PrivateFile = "" }},
	} {
		t.Run(variant.name, func(t *testing.T) {
			raw, _ := json.Marshal(config)
			var candidate approvalDeployment
			_ = json.Unmarshal(raw, &candidate)
			variant.mutate(&candidate)
			raw, _ = json.Marshal(candidate)
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadApprovalConfig(path, &store.Postgres{DB: &sql.DB{}}, "https://id.example.edu", []string{"android"}); !errors.Is(err, errApprovalConfiguration) {
				t.Fatalf("invalid approval configuration accepted: %v", err)
			}
		})
	}
}

func TestApprovalSigningKeyFileRejectsExposureSymlinksAndMultiplePEMBlocks(t *testing.T) {
	path, _ := deploymentFixture(t)
	keyPath := filepath.Join(filepath.Dir(path), "key.pem")
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyPath, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readApprovalKey(keyPath); err == nil {
		t.Fatal("world-readable private key accepted")
	}
	if err := os.Chmod(keyPath, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(path), "linked.pem")
	if err := os.Symlink(keyPath, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readApprovalKey(link); err == nil {
		t.Fatal("symlink key accepted")
	}
	if err := os.WriteFile(keyPath, append(raw, raw...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readApprovalKey(keyPath); err == nil {
		t.Fatal("ambiguous PEM key file accepted")
	}
}
