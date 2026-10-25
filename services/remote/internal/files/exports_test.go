package files

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type exportDownloadRepository struct {
	ExportRepository
	file         Record
	grant        atomic.Int64
	revoked      atomic.Bool
	mu           sync.Mutex
	audits       []string
	calls        atomic.Int32
	holdRenew    bool
	initialLease time.Duration
	renewEntered chan struct{}
	renewOnce    sync.Once
}

func (repo *exportDownloadRepository) AuthorizeExportDownload(ctx context.Context, _ Actor, _ string, _ string) (DownloadPermit, error) {
	if ctx.Err() != nil {
		return DownloadPermit{}, ctx.Err()
	}
	if repo.revoked.Load() {
		return DownloadPermit{}, ErrAccess
	}
	if repo.calls.Add(1) > 1 && repo.holdRenew {
		repo.renewOnce.Do(func() { close(repo.renewEntered) })
		<-ctx.Done()
		return DownloadPermit{}, ctx.Err()
	}
	lease := repo.initialLease
	if lease == 0 {
		lease = 5 * time.Second
	}
	return DownloadPermit{File: repo.file, AuthorizedGrantVersion: repo.grant.Load(), LeaseUntil: time.Now().Add(lease)}, nil
}

func TestExportDownloadLeaseExpiresWhileItsRenewalIsBlocked(t *testing.T) {
	controller, repo, storage, actor := exportDownloadFixture(t, []byte("bytes"))
	repo.holdRenew = true
	repo.initialLease = 900 * time.Millisecond
	repo.renewEntered = make(chan struct{})
	storage.block = true
	done := make(chan error, 1)
	go func() {
		read, err := controller.Open(t.Context(), actor, repo.file.ID)
		if read != nil {
			_ = read.Close()
		}
		done <- err
	}()
	select {
	case <-repo.renewEntered:
	case <-time.After(time.Second):
		t.Fatal("metadata renewal did not begin")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expired download was admitted")
		}
	case <-time.After(600 * time.Millisecond):
		t.Fatal("blocked metadata renewal extended the object read lease")
	}
}
func (repo *exportDownloadRepository) AuditExportDownload(_ context.Context, _ Actor, _ DownloadPermit, _ string, result string) error {
	repo.mu.Lock()
	defer repo.mu.Unlock()
	repo.audits = append(repo.audits, result)
	return nil
}

type exportDownloadStorage struct {
	BlobStore
	data    []byte
	block   bool
	entered chan struct{}
	once    sync.Once
}

func (storage *exportDownloadStorage) PresignHostExport(context.Context, ObjectKey, int64, string, time.Duration) (UploadURL, error) {
	return UploadURL{}, ErrInvalid
}
func (storage *exportDownloadStorage) OpenEncrypted(ctx context.Context, _ ObjectKey, _ int64) (io.ReadCloser, error) {
	if storage.block {
		storage.once.Do(func() { close(storage.entered) })
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return io.NopCloser(bytes.NewReader(storage.data)), nil
}
func exportDownloadFixture(t *testing.T, data []byte) (*Exports, *exportDownloadRepository, *exportDownloadStorage, Actor) {
	t.Helper()
	record := serviceFile(data)
	record.Direction = "from_host"
	record.State = "clean"
	record.CommittedAttempt = record.QuarantineAttempt
	repo := &exportDownloadRepository{file: record}
	repo.grant.Store(1)
	storage := &exportDownloadStorage{data: data, entered: make(chan struct{})}
	service, err := NewService(&serviceRepository{}, storage, &serviceScanner{}, ServiceConfig{Workers: 1, PolicySHA256: digest([]byte("policy")), TaskTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	controller, err := NewExports(repo, storage, service)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(controller.Close)
	return controller, repo, storage, Actor{DeviceID: "99999999-9999-4999-8999-999999999999"}
}
func TestExportReadVerifiesSavedBytesAndAuditsOnlyExplicitlyServedResponses(t *testing.T) {
	for _, scenario := range []string{"served", "corrupt", "partial"} {
		t.Run(scenario, func(t *testing.T) {
			data := []byte("private export bytes")
			controller, repo, storage, actor := exportDownloadFixture(t, data)
			if scenario == "corrupt" {
				storage.data = bytes.Repeat([]byte("x"), len(data))
			}
			read, err := controller.Open(t.Context(), actor, repo.file.ID)
			if err != nil {
				t.Fatal(err)
			}
			if scenario != "partial" {
				actual, err := io.ReadAll(read)
				if scenario == "corrupt" {
					if !errors.Is(err, ErrIntegrity) || len(actual) != 0 {
						t.Fatal("unverified tail was served")
					}
				} else {
					if err != nil || !bytes.Equal(actual, data) {
						t.Fatal("download changed bytes")
					}
					if err := read.Complete(); err != nil {
						t.Fatal(err)
					}
				}
			} else if err := read.Complete(); !errors.Is(err, ErrIntegrity) {
				t.Fatal("unread response was called served")
			}
			if err := read.Close(); err != nil {
				t.Fatal(err)
			}
			if err := read.Close(); err != nil {
				t.Fatal(err)
			}
			repo.mu.Lock()
			defer repo.mu.Unlock()
			expected := scenario
			if scenario == "corrupt" {
				expected = "failed"
			}
			if scenario == "partial" {
				expected = "cancelled"
			}
			if len(repo.audits) != 2 || repo.audits[0] != "opened" || repo.audits[1] != expected {
				t.Fatalf("audit=%v", repo.audits)
			}
		})
	}
}
func TestExportLeaseCancelsPendingStorageHeadersOnRevocationGenerationOrShutdown(t *testing.T) {
	for _, scenario := range []string{"revoked", "generation", "shutdown"} {
		t.Run(scenario, func(t *testing.T) {
			controller, repo, storage, actor := exportDownloadFixture(t, []byte("bytes"))
			storage.block = true
			done := make(chan error, 1)
			go func() {
				read, err := controller.Open(t.Context(), actor, repo.file.ID)
				if read != nil {
					_ = read.Close()
				}
				done <- err
			}()
			select {
			case <-storage.entered:
			case <-time.After(time.Second):
				t.Fatal("storage did not begin")
			}
			switch scenario {
			case "revoked":
				repo.revoked.Store(true)
			case "generation":
				repo.grant.Add(1)
			case "shutdown":
				controller.Close()
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("invalidated headers were accepted")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("pending headers outlived current authority")
			}
			controller.mu.Lock()
			defer controller.mu.Unlock()
			if controller.count != 0 {
				t.Fatal("invalidated download retained admission capacity")
			}
		})
	}
}
func TestExportDownloadAdmissionIsBoundedAndReleasesCapacity(t *testing.T) {
	controller, repo, _, actor := exportDownloadFixture(t, []byte("bytes"))
	one, err := controller.Open(t.Context(), actor, repo.file.ID)
	if err != nil {
		t.Fatal(err)
	}
	two, err := controller.Open(t.Context(), actor, repo.file.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer two.Close()
	if _, err := controller.Open(t.Context(), actor, repo.file.ID); !errors.Is(err, ErrQuota) {
		t.Fatal("device download budget was exceeded")
	}
	_ = one.Close()
	three, err := controller.Open(t.Context(), actor, repo.file.ID)
	if err != nil {
		t.Fatal(err)
	}
	_ = three.Close()
}
