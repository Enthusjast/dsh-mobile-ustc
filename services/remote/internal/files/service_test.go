package files

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/observability"
)

type serviceRepository struct {
	mu          sync.Mutex
	record      Record
	claim       *ScanClaim
	renewErr    error
	completed   int
	completeErr error
	failed      string
	retry       bool
	registers   int
	deletion    *DeletionClaim
	deleted     *bool
}

func (repository *serviceRepository) RegisterUpload(context.Context, Actor, UploadRegistration) (Record, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.registers++
	return repository.record, nil
}
func (repository *serviceRepository) Status(context.Context, Actor, string) (Record, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return repository.record, nil
}
func (repository *serviceRepository) AuthorizeUpload(context.Context, Actor, string) (Record, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return repository.record, nil
}
func (repository *serviceRepository) BeginScan(context.Context, Actor, string) (Record, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.record.State = "scanning"
	return repository.record, nil
}
func (repository *serviceRepository) ClaimScan(context.Context, string) (*ScanClaim, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	claim := repository.claim
	repository.claim = nil
	return claim, nil
}
func (repository *serviceRepository) RenewScan(context.Context, ScanClaim) (time.Time, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return time.Now().Add(time.Second), repository.renewErr
}
func (repository *serviceRepository) CompleteScan(context.Context, ScanClaim) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.completeErr != nil {
		return repository.completeErr
	}
	repository.completed++
	return nil
}
func (repository *serviceRepository) FailScan(_ context.Context, _ ScanClaim, code string, retry bool) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.failed, repository.retry = code, retry
	return nil
}
func (*serviceRepository) Expire(context.Context, int) (int, error) { return 0, nil }
func (repository *serviceRepository) ClaimDeletion(context.Context) (*DeletionClaim, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	claim := repository.deletion
	repository.deletion = nil
	return claim, nil
}
func (repository *serviceRepository) CompleteDeletion(_ context.Context, _ DeletionClaim, success bool) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.deleted = &success
	return nil
}

type serviceScanner struct {
	alwaysClean bool
	block       bool
	entered     chan struct{}
	once        sync.Once
}
type serviceScan struct {
	scanner *serviceScanner
	ctx     context.Context
	body    bytes.Buffer
}

func (scanner *serviceScanner) Begin(ctx context.Context) (Scan, error) {
	return &serviceScan{scanner: scanner, ctx: ctx}, nil
}
func (scan *serviceScan) Write(data []byte) error {
	if scan.ctx.Err() != nil {
		return ErrScanUnavailable
	}
	_, err := scan.body.Write(data)
	return err
}
func (scan *serviceScan) Finish() error {
	data := scan.body.Bytes()
	if bytes.Equal(data, ScannerTestPattern()) {
		if scan.scanner.alwaysClean {
			return nil
		}
		return ErrRejected
	}
	if bytes.HasPrefix(data, []byte("REJECT")) {
		return ErrRejected
	}
	if scan.scanner.block && bytes.HasPrefix(data, []byte("BLOCK")) {
		if scan.scanner.entered != nil {
			scan.scanner.once.Do(func() { close(scan.scanner.entered) })
		}
		<-scan.ctx.Done()
		return ErrScanUnavailable
	}
	return nil
}
func (*serviceScan) Close() error { return nil }

func serviceFile(data []byte) Record {
	return Record{ID: "33333333-3333-4333-8333-333333333333", OrganizationID: "11111111-1111-4111-8111-111111111111", RuntimeID: "66666666-6666-4666-8666-666666666666", SessionID: "22222222-2222-4222-8222-222222222222",
		QuarantineAttempt: "44444444-4444-4444-8444-444444444444", Name: "fixture.bin", SizeBytes: int64(len(data)), SHA256: digest(data), Direction: "to_host", State: "uploading", UploadExpiresAt: time.Now().Add(time.Minute), ExpiresAt: time.Now().Add(time.Hour)}
}

func TestServiceScannerProbeNeverAcceptsAnAlwaysCleanImplementation(t *testing.T) {
	storage, _ := s3Fixture(t, &s3Peer{})
	repository := &serviceRepository{record: serviceFile(nil)}
	scanner := &serviceScanner{alwaysClean: true}
	service, err := NewService(repository, storage, scanner, ServiceConfig{Workers: 1, PolicySHA256: digest([]byte("policy")), TaskTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ProbeScanner(t.Context()); !errors.Is(err, ErrScanUnavailable) || service.Ready() {
		t.Fatal("always-clean scanner became ready")
	}
	if _, err := service.Register(t.Context(), Actor{}, UploadRegistration{}); !errors.Is(err, ErrScanUnavailable) || repository.registers != 0 {
		t.Fatal("unready service consumed metadata quota")
	}
	scanner.alwaysClean = false
	if err := service.ProbeScanner(t.Context()); err != nil || !service.Ready() {
		t.Fatal("operational scanner did not become ready")
	}
	prepared, err := service.Register(t.Context(), Actor{}, UploadRegistration{})
	if err != nil || prepared.Upload == nil || prepared.File.ID != repository.record.ID {
		t.Fatal("file registration was not prepared")
	}
	service.probedAt.Store(time.Now().Add(3 * time.Minute).UnixMilli())
	if service.Ready() {
		t.Fatal("clock rollback extended readiness")
	}
}

func TestServiceScanUsesActualS3StreamBeforeCommittingRepositoryEvidence(t *testing.T) {
	for _, scenario := range []string{"clean", "export", "rejected", "revoked", "lease", "commit", "integrity", "timeout"} {
		t.Run(scenario, func(t *testing.T) {
			peer := &s3Peer{}
			storage, server := s3Fixture(t, peer)
			data := []byte("clean file bytes")
			if scenario == "rejected" {
				data = []byte("REJECT file bytes")
			}
			if scenario == "revoked" || scenario == "lease" || scenario == "timeout" {
				data = []byte("BLOCK file bytes")
			}
			file := serviceFile(data)
			if scenario == "export" {
				file.Direction = "from_host"
			}
			source, _ := file.SourceKey()
			capability, err := storage.PresignUpload(t.Context(), source, file.SizeBytes, file.SHA256, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			putCapability(t, server.Client(), capability, data, 200)
			if scenario == "integrity" {
				file.SHA256 = digest([]byte("different bytes"))
			}
			claim := &ScanClaim{File: file, AttemptID: "55555555-5555-4555-8555-555555555555", LeaseID: "77777777-7777-4777-8777-777777777777", PolicySHA256: digest([]byte("policy")), LeaseUntil: time.Now().Add(2 * time.Second)}
			repository := &serviceRepository{record: file, claim: claim}
			if scenario == "commit" {
				repository.completeErr = ErrUnavailable
			}
			scanner := &serviceScanner{block: scenario == "revoked" || scenario == "lease" || scenario == "timeout"}
			service, err := NewService(repository, storage, scanner, ServiceConfig{Workers: 1, PolicySHA256: claim.PolicySHA256, TaskTimeout: 3 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			metrics := observability.New()
			if err := service.ConfigureMetrics(metrics); err != nil {
				t.Fatal(err)
			}
			if err := service.ConfigureMetrics(observability.New()); !errors.Is(err, ErrInvalid) {
				t.Fatal("live scan observer was replaced")
			}
			if scenario == "revoked" {
				service.renewEvery = 20 * time.Millisecond
				repository.renewErr = ErrAccess
			}
			if scenario == "lease" {
				claim.LeaseUntil = time.Now().Add(250 * time.Millisecond)
				service.renewEvery = time.Second
			}
			if scenario == "timeout" {
				service.config.TaskTimeout = time.Second
			}
			if err := service.ProbeScanner(t.Context()); err != nil {
				t.Fatal(err)
			}
			processed, err := service.ScanNext(t.Context())
			if !processed {
				t.Fatal("file was not claimed")
			}
			expected := map[string]string{"clean": "clean", "export": "clean", "rejected": "rejected", "revoked": "access_denied", "lease": "stale", "commit": "unavailable", "integrity": "integrity", "timeout": "timeout"}[scenario]
			assertScanMetrics(t, metrics, file.Direction, expected)
			if claimed, err := service.ScanNext(t.Context()); claimed || err != nil {
				t.Fatal("empty queue invented a scan", err)
			}
			assertScanMetrics(t, metrics, file.Direction, expected)
			repository.mu.Lock()
			defer repository.mu.Unlock()
			switch scenario {
			case "clean", "export":
				if err != nil || repository.completed != 1 || repository.failed != "" {
					t.Fatalf("clean err=%v completed=%d failed=%s", err, repository.completed, repository.failed)
				}
			case "rejected":
				if !errors.Is(err, ErrRejected) || repository.completed != 0 || repository.failed != "content_rejected" || repository.retry {
					t.Fatal("malware became completed/retryable")
				}
			case "revoked":
				if repository.completed != 0 || repository.failed != "access_revoked" || repository.retry {
					t.Fatalf("revoked err=%v failure=%s", err, repository.failed)
				}
			case "lease":
				if !errors.Is(err, ErrStale) || repository.completed != 0 || repository.failed != "" {
					t.Fatal("expired lease changed repository state")
				}
			case "commit", "integrity", "timeout":
				if err == nil || repository.completed != 0 || repository.failed == "" {
					t.Fatal("failed verification or metadata completion became clean", err)
				}
			}
		})
	}
}

func TestServiceRunShutdownCancelsNetworkWorkWithoutPublishingFailureAsSuccess(t *testing.T) {
	storage, server := s3Fixture(t, &s3Peer{})
	data := []byte("BLOCK in-flight bytes")
	file := serviceFile(data)
	source, _ := file.SourceKey()
	capability, err := storage.PresignUpload(t.Context(), source, file.SizeBytes, file.SHA256, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	putCapability(t, server.Client(), capability, data, 200)
	repository := &serviceRepository{record: file, claim: &ScanClaim{File: file, AttemptID: "55555555-5555-4555-8555-555555555555", LeaseID: "77777777-7777-4777-8777-777777777777", PolicySHA256: digest(nil), LeaseUntil: time.Now().Add(time.Second)}}
	scanner := &serviceScanner{block: true, entered: make(chan struct{})}
	service, err := NewService(repository, storage, scanner, ServiceConfig{Workers: 1, PolicySHA256: digest(nil), TaskTimeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	metrics := observability.New()
	if err := service.ConfigureMetrics(metrics); err != nil {
		t.Fatal(err)
	}
	if err := service.ProbeScanner(t.Context()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { service.Run(ctx); close(done) }()
	select {
	case <-scanner.entered:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("file never entered scanning")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("file workers did not stop")
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.completed != 0 || repository.failed != "" {
		t.Fatal("shutdown completed or rewrote an in-flight intent")
	}
	assertScanMetrics(t, metrics, "to_host", "cancelled")
}
