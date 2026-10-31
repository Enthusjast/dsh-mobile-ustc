package files

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"
)

type deadlinePresigner struct {
	BlobStore
	capability UploadURL
	wait       bool
	deadline   time.Time
}

func (store *deadlinePresigner) sign() (UploadURL, error) {
	if store.wait {
		time.Sleep(max(0, time.Until(store.deadline)+10*time.Millisecond))
	}
	return store.capability, nil
}
func (store *deadlinePresigner) PresignUpload(context.Context, ObjectKey, int64, string, time.Duration) (UploadURL, error) {
	return store.sign()
}
func (store *deadlinePresigner) PresignHostExport(context.Context, ObjectKey, int64, string, time.Duration) (UploadURL, error) {
	return store.sign()
}

type deadlineExportRepository struct {
	ExportRepository
	record Record
}

func (repo *deadlineExportRepository) AuthorizeExportUpload(context.Context, Actor, HostBinding, string) (Record, error) {
	return repo.record, nil
}

func TestUploadControllersRejectExpiredLateOrOverlongPresignedCapabilities(t *testing.T) {
	for _, direction := range []string{"to_host", "from_host"} {
		for _, scenario := range []string{"expired", "late", "overlong", "file-window", "retention-window", "valid"} {
			t.Run(direction+"/"+scenario, func(t *testing.T) {
				record := serviceFile([]byte("fixture"))
				record.Direction = direction
				record.UploadExpiresAt = time.Now().Add(2 * time.Second)
				expires := record.UploadExpiresAt.Add(-100 * time.Millisecond)
				if scenario == "expired" {
					expires = time.Now().Add(-time.Second)
				} else if scenario == "overlong" {
					expires = record.UploadExpiresAt.Add(time.Second)
				} else if scenario == "late" {
					expires = record.UploadExpiresAt
				} else if scenario == "file-window" || scenario == "retention-window" {
					deadline := record.UploadExpiresAt
					record.UploadExpiresAt = deadline.Add(10 * time.Second)
					expires = deadline.Add(time.Second)
					if scenario == "file-window" {
						record.ExpiresAt = deadline
					} else {
						record.RetainUntil = deadline
					}
				}
				storage := &deadlinePresigner{capability: UploadURL{URL: "https://objects.example/PRIVATE_SIGNED_CAPABILITY", Method: "PUT", ExpiresAt: expires}, wait: scenario == "late", deadline: record.UploadExpiresAt}
				service, err := NewService(&serviceRepository{record: record}, storage, &serviceScanner{}, ServiceConfig{Workers: 1, PolicySHA256: digest(nil), TaskTimeout: time.Second})
				if err != nil {
					t.Fatal(err)
				}
				service.healthy.Store(true)
				service.probedAt.Store(time.Now().UnixMilli())
				var prepared UploadPrepared
				if direction == "to_host" {
					prepared, err = service.Upload(t.Context(), Actor{}, record.ID)
				} else {
					exports, createErr := NewExports(&deadlineExportRepository{record: record}, storage, service)
					if createErr != nil {
						t.Fatal(createErr)
					}
					defer exports.Close()
					prepared, err = exports.Upload(t.Context(), Actor{}, HostBinding{}, record.ID)
				}
				if scenario == "valid" {
					if err != nil || prepared.Upload == nil || !prepared.Upload.ExpiresAt.Equal(expires) {
						t.Fatal("live bounded upload capability rejected", err)
					}
				} else if !errors.Is(err, ErrStale) || prepared.Upload != nil {
					t.Fatal("expired or overlong capability was exposed", err)
				}
			})
		}
	}
}

type lateDownloadAudit struct{ *exportDownloadRepository }

func (repo *lateDownloadAudit) AuditExportDownload(ctx context.Context, actor Actor, permit DownloadPermit, id, result string) error {
	if result == "opened" {
		time.Sleep(max(0, time.Until(permit.LeaseUntil)+10*time.Millisecond))
	}
	return repo.exportDownloadRepository.AuditExportDownload(ctx, actor, permit, id, result)
}

type noLateObjectOpen struct {
	ExportBlobStore
	opens atomic.Int32
}

func (store *noLateObjectOpen) OpenEncrypted(context.Context, ObjectKey, int64) (io.ReadCloser, error) {
	store.opens.Add(1)
	return nil, ErrBlobUnavailable
}

func TestExportOpenDoesNotTouchStorageAfterAuditOutlivesItsLease(t *testing.T) {
	record := serviceFile([]byte("fixture"))
	record.Direction, record.State, record.CommittedAttempt = "from_host", "clean", record.QuarantineAttempt
	repository := &lateDownloadAudit{&exportDownloadRepository{file: record, initialLease: 100 * time.Millisecond}}
	storage := &noLateObjectOpen{}
	service, err := NewService(&serviceRepository{}, storage, &serviceScanner{}, ServiceConfig{Workers: 1, PolicySHA256: digest(nil), TaskTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	exports, err := NewExports(repository, storage, service)
	if err != nil {
		t.Fatal(err)
	}
	defer exports.Close()
	read, err := exports.Open(t.Context(), Actor{DeviceID: "99999999-9999-4999-8999-999999999999"}, record.ID)
	if read != nil {
		_ = read.Close()
	}
	if !errors.Is(err, ErrAccess) || storage.opens.Load() != 0 {
		t.Fatal("expired download opened object storage after its audit wait", err)
	}
}
