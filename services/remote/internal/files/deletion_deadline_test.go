package files

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type deletionStorageProbe struct {
	BlobStore
	calls atomic.Int32
}

func (storage *deletionStorageProbe) Delete(context.Context, ObjectKey) error {
	storage.calls.Add(1)
	return nil // Deliberately ignores context; the controller must gate entry.
}

func TestCleanupControllerDoesNotInvokeStorageWithoutAUsableLease(t *testing.T) {
	for _, scenario := range []string{"expired", "margin", "cancelled", "valid"} {
		t.Run(scenario, func(t *testing.T) {
			file := serviceFile(nil)
			until := time.Now().Add(30 * time.Second)
			if scenario == "expired" {
				until = time.Now().Add(-time.Second)
			} else if scenario == "margin" {
				until = time.Now().Add(50 * time.Millisecond)
			}
			repo := &serviceRepository{deletion: &DeletionClaim{FileID: file.ID, OrganizationID: file.OrganizationID, SessionID: file.SessionID,
				Kind: Quarantine, AttemptID: file.QuarantineAttempt, LeaseID: file.QuarantineAttempt, LeaseUntil: until}}
			storage := &deletionStorageProbe{}
			service, err := NewService(repo, storage, &serviceScanner{}, ServiceConfig{Workers: 1, PolicySHA256: digest(nil), TaskTimeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if scenario == "cancelled" {
				cancel()
			}
			claimed, err := service.DeleteNext(ctx)
			if !claimed {
				t.Fatal("fixture lost its queued cleanup job")
			}
			if scenario == "valid" {
				if err != nil || storage.calls.Load() != 1 || repo.deleted == nil || !*repo.deleted {
					t.Fatal("valid cleanup was not deleted and acknowledged", err)
				}
			} else {
				want := ErrStale
				if scenario == "cancelled" {
					want = context.Canceled
				}
				if !errors.Is(err, want) || storage.calls.Load() != 0 || repo.deleted != nil {
					t.Fatal("unusable cleanup authority reached storage or success acknowledgement", err)
				}
			}
		})
	}
}
