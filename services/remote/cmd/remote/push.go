package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"dsh-mobile-ustc/services/remote/internal/push"
	"dsh-mobile-ustc/services/remote/internal/relay"
	"dsh-mobile-ustc/services/remote/internal/store"
)

var errPushConfiguration = errors.New("remote service protected notification configuration is invalid")

type pushDeployment struct {
	Enabled    *bool `json:"enabled"`
	Encryption struct {
		Active string            `json:"active_key_id"`
		Keys   map[string]string `json:"keys"`
		Lookup string            `json:"lookup_key"`
	} `json:"encryption"`
	FCM struct {
		Project            string `json:"project_id"`
		Package            string `json:"package_name"`
		ServiceAccountFile string `json:"service_account_file"`
	} `json:"fcm"`
	Workers int `json:"workers"`
}
type pushRuntime struct {
	repository *store.PushStore
	sender     *push.FCM
	workers    int
}

func loadPushRuntime(path string, database *store.Postgres, issuer string, approvals *relay.ApprovalConfig) (*pushRuntime, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := readProtectedFile(path, 64<<10)
	if err != nil {
		return nil, errPushConfiguration
	}
	defer clear(raw)
	var config pushDeployment
	if strictFileJSON(raw, &config) != nil || config.Enabled == nil {
		return nil, errPushConfiguration
	}
	if !*config.Enabled {
		return nil, nil
	}
	if config.Workers < 1 || config.Workers > 16 {
		return nil, errPushConfiguration
	}
	lookup, err := base64.StdEncoding.Strict().DecodeString(config.Encryption.Lookup)
	if err != nil || len(lookup) != 32 {
		return nil, errPushConfiguration
	}
	defer clear(lookup)
	keys := map[string][]byte{}
	defer func() {
		for _, key := range keys {
			clear(key)
		}
	}()
	for id, encoded := range config.Encryption.Keys {
		key, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil || len(key) != 32 {
			clear(key)
			return nil, errPushConfiguration
		}
		keys[id] = key
	}
	cipher, err := push.NewCipher(config.Encryption.Active, keys, lookup)
	if err != nil {
		return nil, errPushConfiguration
	}
	credential, err := readProtectedFile(relativeFile(path, config.FCM.ServiceAccountFile), 64<<10)
	if err != nil {
		return nil, errPushConfiguration
	}
	defer clear(credential)
	source, err := push.NewServiceAccountTokens(credential, nil)
	if err != nil {
		return nil, errPushConfiguration
	}
	sender, err := push.NewFCM(config.FCM.Project, config.FCM.Package, source, nil)
	if err != nil {
		return nil, errPushConfiguration
	}
	var control *store.ApprovalControl
	if approvals != nil {
		control, _ = approvals.Control.(*store.ApprovalControl)
	}
	fingerprint := sha256.Sum256(lookup)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	repository, err := store.NewPushStore(ctx, database, cipher, issuer, config.FCM.Project, config.FCM.Package, hex.EncodeToString(fingerprint[:]), control)
	if err != nil {
		return nil, errPushConfiguration
	}
	return &pushRuntime{repository: repository, sender: sender, workers: config.Workers}, nil
}
func (runtime *pushRuntime) Run(ctx context.Context) {
	var workers sync.WaitGroup
	for range runtime.workers {
		workers.Add(1)
		go func() { defer workers.Done(); push.Run(ctx, runtime.repository, runtime.sender) }()
	}
	workers.Wait()
}
