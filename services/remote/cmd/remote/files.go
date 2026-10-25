package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/files"
	"dsh-mobile-ustc/services/remote/internal/store"
	"github.com/aws/aws-sdk-go-v2/aws"
)

var errFileConfiguration = errors.New("remote service protected file storage/scanner configuration is invalid")

type fileDeployment struct {
	Storage struct {
		Endpoint        string `json:"endpoint"`
		Region          string `json:"region"`
		Bucket          string `json:"bucket"`
		KMSKeyID        string `json:"kms_key_id"`
		CredentialsFile string `json:"credentials_file"`
		CAFile          string `json:"ca_file"`
	} `json:"storage"`
	Scanner struct {
		Network        string `json:"network"`
		Address        string `json:"address"`
		ServerName     string `json:"server_name"`
		CAFile         string `json:"ca_file"`
		PolicyFile     string `json:"policy_file"`
		TimeoutSeconds int64  `json:"timeout_seconds"`
	} `json:"scanner"`
	Limits struct {
		OrganizationBytes int64 `json:"organization_bytes"`
		UserBytes         int64 `json:"user_bytes"`
		SessionBytes      int64 `json:"session_bytes"`
		OrganizationFiles int64 `json:"organization_files"`
		UserFiles         int64 `json:"user_files"`
		SessionFiles      int64 `json:"session_files"`
		UploadURLSeconds  int64 `json:"upload_url_seconds"`
		AbandonSeconds    int64 `json:"abandon_seconds"`
		RetainSeconds     int64 `json:"retain_seconds"`
	} `json:"limits"`
	Workers            int   `json:"workers"`
	TaskTimeoutSeconds int64 `json:"task_timeout_seconds"`
}
type fileCredentials struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token,omitempty"`
}
type fileRuntime struct {
	service  *files.Service
	storage  *files.S3
	handoffs *files.Handoffs
}

func (runtime *fileRuntime) Close() {
	if runtime != nil {
		_ = runtime.storage.Close()
	}
}

func readProtectedFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() <= 0 || info.Size() > limit {
		return nil, errFileConfiguration
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errFileConfiguration
	}
	defer file.Close()
	actual, err := file.Stat()
	if err != nil || !os.SameFile(info, actual) {
		return nil, errFileConfiguration
	}
	body, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(body)) > limit {
		clear(body)
		return nil, errFileConfiguration
	}
	return body, nil
}
func strictFileJSON(body []byte, target any) error {
	if auth.ValidateJSONObject(body) != nil {
		return errFileConfiguration
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return errFileConfiguration
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) {
		return errFileConfiguration
	}
	return nil
}
func relativeFile(base, path string) string {
	if path == "" {
		return ""
	}
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(filepath.Dir(base), path)
}
func fileRoots(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 1<<20 {
		return nil, errFileConfiguration
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errFileConfiguration
	}
	defer file.Close()
	actual, err := file.Stat()
	if err != nil || !os.SameFile(info, actual) {
		return nil, errFileConfiguration
	}
	body, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(body) > 1<<20 {
		return nil, errFileConfiguration
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(body) {
		return nil, errFileConfiguration
	}
	return roots, nil
}
func fileSeconds(value int64, minimum, maximum time.Duration) (time.Duration, error) {
	if value < int64(minimum/time.Second) || value > int64(maximum/time.Second) {
		return 0, errFileConfiguration
	}
	return time.Duration(value) * time.Second, nil
}

// The policy digest is taken from the deployed clamd configuration, not an
// operator-supplied success label. Deployment must point that daemon at the
// same file; the runtime probe also requires an actual EICAR rejection.
func fileScannerPolicy(path string) (string, error) {
	body, err := readProtectedFile(path, 256<<10)
	if err != nil {
		return "", err
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			return "", errFileConfiguration
		}
		if parts[0] == "Include" {
			return "", errFileConfiguration
		}
		switch parts[0] {
		case "StreamMaxLength", "MaxFileSize", "MaxScanSize", "AlertExceedsMax", "ScanArchive", "MaxRecursion", "MaxFiles", "MaxScanTime":
			if _, exists := values[parts[0]]; exists || len(parts) != 2 {
				return "", errFileConfiguration
			}
			values[parts[0]] = parts[1]
		}
	}
	if values["AlertExceedsMax"] != "yes" || values["ScanArchive"] != "yes" {
		return "", errFileConfiguration
	}
	for _, name := range []string{"StreamMaxLength", "MaxFileSize", "MaxScanSize"} {
		text := values[name]
		factor := int64(1)
		if len(text) > 0 {
			switch text[len(text)-1] {
			case 'K', 'k':
				factor = 1 << 10
				text = text[:len(text)-1]
			case 'M', 'm':
				factor = 1 << 20
				text = text[:len(text)-1]
			case 'G', 'g':
				factor = 1 << 30
				text = text[:len(text)-1]
			}
		}
		amount, err := strconv.ParseInt(text, 10, 64)
		if err != nil || amount <= 0 || amount > (1<<40)/factor || amount*factor < files.MaxUploadBytes {
			return "", errFileConfiguration
		}
	}
	for _, name := range []string{"MaxRecursion", "MaxFiles", "MaxScanTime"} {
		amount, err := strconv.ParseInt(values[name], 10, 64)
		if err != nil || amount <= 0 || amount > 1_000_000_000 {
			return "", errFileConfiguration
		}
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]), nil
}

func loadFileRuntime(path string, database *store.Postgres) (*fileRuntime, error) {
	if path == "" {
		return nil, nil
	}
	body, err := readProtectedFile(path, 64<<10)
	if err != nil {
		return nil, err
	}
	defer clear(body)
	var config fileDeployment
	if strictFileJSON(body, &config) != nil {
		return nil, errFileConfiguration
	}
	credentialsRaw, err := readProtectedFile(relativeFile(path, config.Storage.CredentialsFile), 16<<10)
	if err != nil {
		return nil, err
	}
	defer clear(credentialsRaw)
	var keys fileCredentials
	if strictFileJSON(credentialsRaw, &keys) != nil || keys.AccessKeyID == "" || keys.SecretAccessKey == "" {
		return nil, errFileConfiguration
	}
	roots, err := fileRoots(relativeFile(path, config.Storage.CAFile))
	if err != nil {
		return nil, err
	}
	storage, err := files.NewS3(files.S3Config{Endpoint: config.Storage.Endpoint, Region: config.Storage.Region, Bucket: config.Storage.Bucket, KMSKeyID: config.Storage.KMSKeyID, Roots: roots},
		aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: keys.AccessKeyID, SecretAccessKey: keys.SecretAccessKey, SessionToken: keys.SessionToken, Source: "remote-file-configuration"}, nil
		}))
	if err != nil {
		return nil, errFileConfiguration
	}
	complete := false
	defer func() {
		if !complete {
			_ = storage.Close()
		}
	}()
	policy, err := fileScannerPolicy(relativeFile(path, config.Scanner.PolicyFile))
	if err != nil {
		return nil, err
	}
	scanTimeout, err := fileSeconds(config.Scanner.TimeoutSeconds, time.Second, 15*time.Minute)
	if err != nil {
		return nil, err
	}
	scanConfig := files.ClamAVConfig{Network: config.Scanner.Network, Address: config.Scanner.Address, Timeout: scanTimeout}
	if config.Scanner.Network == "tcp" {
		scanRoots, err := fileRoots(relativeFile(path, config.Scanner.CAFile))
		if err != nil {
			return nil, err
		}
		scanConfig.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: config.Scanner.ServerName, RootCAs: scanRoots}
	} else if config.Scanner.ServerName != "" || config.Scanner.CAFile != "" {
		return nil, errFileConfiguration
	}
	scanner, err := files.NewClamAV(scanConfig)
	if err != nil {
		return nil, errFileConfiguration
	}
	urlTTL, err := fileSeconds(config.Limits.UploadURLSeconds, time.Minute, 15*time.Minute)
	if err != nil {
		return nil, err
	}
	abandon, err := fileSeconds(config.Limits.AbandonSeconds, time.Minute, 48*time.Hour)
	if err != nil {
		return nil, err
	}
	retain, err := fileSeconds(config.Limits.RetainSeconds, time.Minute, 90*24*time.Hour)
	if err != nil {
		return nil, err
	}
	repository, err := store.NewFileStore(database, files.Limits{OrganizationBytes: config.Limits.OrganizationBytes, UserBytes: config.Limits.UserBytes, SessionBytes: config.Limits.SessionBytes,
		OrganizationFiles: config.Limits.OrganizationFiles, UserFiles: config.Limits.UserFiles, SessionFiles: config.Limits.SessionFiles, UploadURLTTL: urlTTL, AbandonAfter: abandon, RetainFor: retain})
	if err != nil {
		return nil, errFileConfiguration
	}
	task, err := fileSeconds(config.TaskTimeoutSeconds, time.Second, 15*time.Minute)
	if err != nil {
		return nil, err
	}
	service, err := files.NewService(repository, storage, scanner, files.ServiceConfig{Workers: config.Workers, PolicySHA256: policy, TaskTimeout: task})
	if err != nil {
		return nil, errFileConfiguration
	}
	handoffs, err := files.NewHandoffs(repository, storage, policy)
	if err != nil {
		return nil, errFileConfiguration
	}
	complete = true
	return &fileRuntime{service: service, storage: storage, handoffs: handoffs}, nil
}
