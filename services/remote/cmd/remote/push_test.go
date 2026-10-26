package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dsh-mobile-ustc/services/remote/internal/store"
	"dsh-mobile-ustc/services/remote/internal/testsupport"
)

func TestPushRuntimeProtectedConfigurationAndDisabledDefault(t *testing.T) {
	if value, err := loadPushRuntime("", nil, "", nil); err != nil || value != nil {
		t.Fatal("push enabled without configuration")
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "push.json")
	if err := os.WriteFile(path, []byte(`{"enabled":false}`), 0600); err != nil {
		t.Fatal(err)
	}
	if value, err := loadPushRuntime(path, nil, "", nil); err != nil || value != nil {
		t.Fatal("explicit disable initialized credentials")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPushRuntime(path, nil, "", nil); err == nil {
		t.Fatal("publicly readable push configuration accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`{}`, `{"enabled":true,"unexpected":"PRIVATE"}`, `{"enabled":true,"enabled":false}`, `{"enabled":true,"workers":99}`} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadPushRuntime(path, nil, "", nil); err == nil || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("invalid configuration was accepted or leaked")
		}
	}
}
func TestPushRuntimeLoadsRealProtectedKeysAgainstIsolatedPostgres(t *testing.T) {
	_, db := testsupport.PostgresDatabase(t)
	dir := t.TempDir()
	credential := filepath.Join(dir, "service-account.json")
	path := filepath.Join(dir, "push.json")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	account, _ := json.Marshal(map[string]string{"type": "service_account", "client_email": "sender@fixture-project.iam.gserviceaccount.com", "private_key_id": "fixture", "private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), "token_uri": "https://oauth2.googleapis.com/token"})
	if err = os.WriteFile(credential, account, 0600); err != nil {
		t.Fatal(err)
	}
	lookup, aes := make([]byte, 32), make([]byte, 32)
	_, _ = rand.Read(lookup)
	_, _ = rand.Read(aes)
	config := map[string]any{"enabled": true, "workers": 2, "encryption": map[string]any{"active_key_id": "one", "keys": map[string]string{"one": base64.StdEncoding.EncodeToString(aes)}, "lookup_key": base64.StdEncoding.EncodeToString(lookup)}, "fcm": map[string]string{"project_id": "fixture-project", "package_name": "cn.edu.ustc.dsh.mobile", "service_account_file": "service-account.json"}}
	raw, _ := json.Marshal(config)
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	runtime, err := loadPushRuntime(path, &store.Postgres{DB: db}, "https://id.example.edu", nil)
	if err != nil || runtime == nil || runtime.workers != 2 {
		t.Fatalf("protected runtime: %v", err)
	}
	var known string
	expected := sha256.Sum256(lookup)
	if db.QueryRow(`select lookup_key_sha256 from push_key_metadata`).Scan(&known) != nil || known != hex.EncodeToString(expected[:]) {
		t.Fatal("lookup-key continuity was not stored")
	}
	if err = os.Chmod(credential, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = loadPushRuntime(path, &store.Postgres{DB: db}, "https://id.example.edu", nil); err == nil {
		t.Fatal("public service-account private key accepted")
	}
}
