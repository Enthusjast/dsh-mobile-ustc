package main

import (
	"crypto/tls"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"dsh-mobile-ustc/services/remote/internal/testsupport"
)

func TestRelayDeploymentRequiresProtectedMatchingMutualTLSIdentity(t *testing.T) {
	if config, err := loadRelayDeployment("", ""); config != nil || err != nil {
		t.Fatal("default enabled private relay")
	}
	root := t.TempDir()
	node := "aaaaaaaa-1111-4111-8111-111111111111"
	ca := testsupport.NewRelayCA(t)
	cert, key, _ := ca.Issue(t, node)
	write := func(name string, raw []byte) string {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	write("ca.pem", ca.PEM)
	write("node.pem", cert)
	write("node.key", key)
	base := func() map[string]any {
		return map[string]any{"listen_addr": "127.0.0.1:9041", "origin": "https://127.0.0.1:9041", "ca_file": "ca.pem", "certificate_file": "node.pem", "key_file": "node.key", "max_proxy_connections": 64}
	}
	for _, test := range []struct {
		name, id string
		change   func(map[string]any)
		valid    bool
	}{
		{name: "valid", id: node, valid: true},
		{name: "unregistered node"},
		{name: "wrong node", id: "bbbbbbbb-1111-4111-8111-111111111111"},
		{name: "public binding", id: node, change: func(c map[string]any) { c["listen_addr"] = "0.0.0.0:9041" }},
		{name: "ambiguous binding", id: node, change: func(c map[string]any) { c["listen_addr"] = "localhost:9041" }},
		{name: "unencrypted origin", id: node, change: func(c map[string]any) { c["origin"] = "http://127.0.0.1:9041" }},
		{name: "wrong hostname", id: node, change: func(c map[string]any) { c["origin"] = "https://192.0.2.1:9041" }},
		{name: "oversized budget", id: node, change: func(c map[string]any) { c["max_proxy_connections"] = 12001 }},
		{name: "missing key", id: node, change: func(c map[string]any) { c["key_file"] = "" }},
		{name: "unknown TLS option", id: node, change: func(c map[string]any) { c["insecure_skip_verify"] = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := base()
			if test.change != nil {
				test.change(config)
			}
			raw, _ := json.Marshal(config)
			path := write("config.json", raw)
			deployment, err := loadRelayDeployment(path, test.id)
			if !test.valid {
				if err == nil || deployment != nil {
					t.Fatal("accepted invalid relay deployment")
				}
				return
			}
			if err != nil || deployment == nil {
				t.Fatal(err)
			}
			if deployment.serverTLS.ClientAuth != tls.RequireAndVerifyClientCert || deployment.clientTLS.InsecureSkipVerify || deployment.serverTLS.MinVersion != tls.VersionTLS13 || deployment.clientTLS.MinVersion != tls.VersionTLS13 {
				t.Fatal("TLS verification weakened")
			}
		})
	}
	raw, _ := json.Marshal(base())
	path := write("public-config.json", raw)
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if config, err := loadRelayDeployment(path, node); err == nil || config != nil {
		t.Fatal("accepted unprotected routing configuration")
	}
	if err := os.Chmod(filepath.Join(root, "node.key"), 0644); err != nil {
		t.Fatal(err)
	}
	path = write("private-config.json", raw)
	if config, err := loadRelayDeployment(path, node); err == nil || config != nil {
		t.Fatal("accepted unprotected node key")
	}
}
