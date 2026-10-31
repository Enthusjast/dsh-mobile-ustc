package files

import (
	"context"
	"errors"
	"io"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"dsh-mobile-ustc/services/remote/internal/observability"
)

type Repository interface {
	RegisterUpload(context.Context, Actor, UploadRegistration) (Record, error)
	Status(context.Context, Actor, string) (Record, error)
	AuthorizeUpload(context.Context, Actor, string) (Record, error)
	BeginScan(context.Context, Actor, string) (Record, error)
	ClaimScan(context.Context, string) (*ScanClaim, error)
	RenewScan(context.Context, ScanClaim) (time.Time, error)
	CompleteScan(context.Context, ScanClaim) error
	FailScan(context.Context, ScanClaim, string, bool) error
	Expire(context.Context, int) (int, error)
	ClaimDeletion(context.Context) (*DeletionClaim, error)
	CompleteDeletion(context.Context, DeletionClaim, bool) error
}

type BlobStore interface {
	PresignUpload(context.Context, ObjectKey, int64, string, time.Duration) (UploadURL, error)
	OpenEncrypted(context.Context, ObjectKey, int64) (io.ReadCloser, error)
	PutVerified(context.Context, ObjectKey, *VerifiedReader) error
	Delete(context.Context, ObjectKey) error
}
type Scanner interface {
	Begin(context.Context) (Scan, error)
}

type ServiceConfig struct {
	Workers      int
	PolicySHA256 string
	TaskTimeout  time.Duration
}
type Service struct {
	repository  Repository
	storage     BlobStore
	scanner     Scanner
	config      ServiceConfig
	healthy     atomic.Bool
	probedAt    atomic.Int64
	running     atomic.Bool
	renewEvery  time.Duration
	metricsOnce sync.Once
	metrics     *observability.Metrics
}

func NewService(repository Repository, storage BlobStore, scanner Scanner, config ServiceConfig) (*Service, error) {
	if repository == nil || storage == nil || scanner == nil || config.Workers < 1 || config.Workers > 8 || config.TaskTimeout < time.Second || config.TaskTimeout > 15*time.Minute {
		return nil, ErrInvalid
	}
	if _, valid := checksum(config.PolicySHA256); !valid {
		return nil, ErrInvalid
	}
	return &Service{repository: repository, storage: storage, scanner: scanner, config: config, renewEvery: 5 * time.Second}, nil
}

// ScannerTestPattern builds the standard harmless EICAR diagnostic bytes in
// memory. No test file is created in the workspace or sent to object storage.
func ScannerTestPattern() []byte {
	return []byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}" + "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
}

func (service *Service) ProbeScanner(ctx context.Context) error {
	for index, data := range [][]byte{[]byte("DSH remote file scanner health check"), ScannerTestPattern()} {
		scan, err := service.scanner.Begin(ctx)
		if err == nil {
			err = scan.Write(data)
			if err == nil {
				err = scan.Finish()
			}
			_ = scan.Close()
		}
		if index == 0 && err != nil || index == 1 && !errors.Is(err, ErrRejected) {
			service.healthy.Store(false)
			service.probedAt.Store(time.Now().UnixMilli())
			return ErrScanUnavailable
		}
	}
	service.probedAt.Store(time.Now().UnixMilli())
	service.healthy.Store(true)
	return nil
}

func (service *Service) Ready() bool {
	age := time.Since(time.UnixMilli(service.probedAt.Load()))
	return service.healthy.Load() && age >= 0 && age < 2*time.Minute
}

type UploadPrepared struct {
	File   Status     `json:"file"`
	Upload *UploadURL `json:"upload,omitempty"`
}

func uploadDeadline(record Record) time.Time {
	return minTime(record.UploadExpiresAt, minTime(record.ExpiresAt, record.RetainUntil))
}

func currentUploadCapability(record Record, capability UploadURL) bool {
	return capability.ExpiresAt.After(time.Now()) && !capability.ExpiresAt.After(uploadDeadline(record))
}

func (service *Service) Register(ctx context.Context, actor Actor, input UploadRegistration) (UploadPrepared, error) {
	if !service.Ready() {
		return UploadPrepared{}, ErrScanUnavailable
	}
	record, err := service.repository.RegisterUpload(ctx, actor, input)
	if err != nil {
		return UploadPrepared{}, err
	}
	if record.State != "uploading" {
		return UploadPrepared{File: record.Status()}, nil
	}
	return service.Upload(ctx, actor, record.ID)
}

func (service *Service) Upload(ctx context.Context, actor Actor, id string) (UploadPrepared, error) {
	if !service.Ready() {
		return UploadPrepared{}, ErrScanUnavailable
	}
	record, err := service.repository.AuthorizeUpload(ctx, actor, id)
	if err != nil {
		return UploadPrepared{}, err
	}
	lifetime := time.Until(uploadDeadline(record)).Truncate(time.Second)
	if lifetime < time.Second {
		return UploadPrepared{}, ErrStale
	}
	if lifetime > 15*time.Minute {
		lifetime = 15 * time.Minute
	}
	key, err := record.SourceKey()
	if err != nil {
		return UploadPrepared{}, ErrUnavailable
	}
	capability, err := service.storage.PresignUpload(ctx, key, record.SizeBytes, record.SHA256, lifetime)
	if err != nil {
		return UploadPrepared{}, err
	}
	if ctx.Err() != nil {
		return UploadPrepared{}, ErrUnavailable
	}
	if !currentUploadCapability(record, capability) {
		return UploadPrepared{}, ErrStale
	}
	return UploadPrepared{File: record.Status(), Upload: &capability}, nil
}

func (service *Service) Status(ctx context.Context, actor Actor, id string) (Status, error) {
	record, err := service.repository.Status(ctx, actor, id)
	return record.Status(), err
}
func (service *Service) Commit(ctx context.Context, actor Actor, id string) (Status, error) {
	if !service.Ready() {
		return Status{}, ErrScanUnavailable
	}
	record, err := service.repository.BeginScan(ctx, actor, id)
	return record.Status(), err
}

// Run owns bounded workers. On shutdown in-flight attempts keep their recorded
// candidate keys and expire naturally; a later worker reclaims them with a new
// lease and key, never by replaying an old request body.
func (service *Service) Run(ctx context.Context) {
	if !service.running.CompareAndSwap(false, true) {
		return
	}
	defer service.running.Store(false)
	var workers sync.WaitGroup
	workers.Add(service.config.Workers + 2)
	for range service.config.Workers {
		go func() {
			defer workers.Done()
			service.repeat(ctx, 250*time.Millisecond, "scan", func(ctx context.Context) error { _, err := service.ScanNext(ctx); return err })
		}()
	}
	go func() {
		defer workers.Done()
		service.repeat(ctx, time.Minute, "scanner", func(ctx context.Context) error {
			probe, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			return service.ProbeScanner(probe)
		})
	}()
	go func() {
		defer workers.Done()
		service.repeat(ctx, time.Second, "cleanup", func(ctx context.Context) error {
			attempt, cancel := context.WithTimeout(ctx, 2*time.Second)
			_, err := service.repository.Expire(attempt, 128)
			cancel()
			if err != nil {
				return err
			}
			_, err = service.DeleteNext(ctx)
			return err
		})
	}()
	workers.Wait()
}

func (service *Service) repeat(ctx context.Context, period time.Duration, name string, operation func(context.Context) error) {
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	unavailable := false
	for ctx.Err() == nil {
		err := operation(ctx)
		if ctx.Err() != nil {
			return
		}
		if (err != nil) != unavailable {
			unavailable = err != nil
			log.Printf("remote files %s unavailable=%t", name, unavailable)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (service *Service) ScanNext(ctx context.Context) (bool, error) {
	if !service.Ready() {
		return false, ErrScanUnavailable
	}
	admit, cancel := context.WithTimeout(ctx, 2*time.Second)
	claim, err := service.repository.ClaimScan(admit, service.config.PolicySHA256)
	cancel()
	if err != nil || claim == nil {
		return false, err
	}
	return true, service.scan(ctx, *claim)
}

func (service *Service) scan(parent context.Context, claim ScanClaim) (result error) {
	started := time.Now()
	bounded, stop := context.WithTimeout(parent, service.config.TaskTimeout)
	defer stop()
	ctx, cancel := context.WithCancelCause(bounded)
	defer cancel(nil)
	defer func() {
		err := result
		if err != nil && context.Cause(ctx) != nil {
			err = context.Cause(ctx)
		}
		outcome := FileOperationResult(err)
		if err == nil {
			outcome = "clean"
		}
		service.metrics.FileScanAttempt(claim.File.Direction, outcome, time.Since(started))
	}()
	leaseTimer := time.AfterFunc(max(0, time.Until(claim.LeaseUntil)-100*time.Millisecond), func() { cancel(ErrStale) })
	defer leaseTimer.Stop()
	stopRenew, renewDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(renewDone)
		ticker := time.NewTicker(service.renewEvery)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-stopRenew:
				return
			case <-ticker.C:
				attempt, closeAttempt := context.WithTimeout(ctx, 2*time.Second)
				until, err := service.repository.RenewScan(attempt, claim)
				closeAttempt()
				if err != nil {
					cancel(err)
					return
				}
				leaseTimer.Reset(max(0, time.Until(until)-100*time.Millisecond))
			}
		}
	}()
	err := service.copyVerified(ctx, claim)
	if err == nil {
		if ctx.Err() != nil {
			err = context.Cause(ctx)
		} else {
			err = service.repository.CompleteScan(ctx, claim)
		}
	}
	close(stopRenew)
	<-renewDone
	if err == nil {
		return nil
	}
	if parent.Err() != nil {
		return parent.Err()
	}
	cause := context.Cause(ctx)
	if errors.Is(cause, ErrStale) || errors.Is(err, ErrStale) {
		return ErrStale
	}
	code, retry := scanFailure(err)
	if cause != nil {
		code, retry = scanFailure(cause)
	}
	record, closeRecord := context.WithTimeout(context.Background(), 2*time.Second)
	defer closeRecord()
	if failure := service.repository.FailScan(record, claim, code, retry); failure != nil && !errors.Is(failure, ErrStale) {
		return failure
	}
	return err
}

func (service *Service) copyVerified(ctx context.Context, claim ScanClaim) error {
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	sourceKey, err := claim.File.SourceKey()
	if err != nil {
		return ErrInvalid
	}
	source, err := service.storage.OpenEncrypted(ctx, sourceKey, claim.File.SizeBytes)
	if err != nil {
		return err
	}
	defer source.Close()
	scan, err := service.scanner.Begin(ctx)
	if err != nil {
		return ErrScanUnavailable
	}
	defer scan.Close()
	verify := NewVerifiedReader
	if claim.File.Direction == "from_host" {
		verify = NewExportVerifiedReader
	}
	reader, err := verify(source, scan, claim.File.SizeBytes, claim.File.SHA256)
	if err != nil {
		return err
	}
	key, err := claim.Key()
	if err != nil {
		return ErrInvalid
	}
	return service.storage.PutVerified(ctx, key, reader)
}

func scanFailure(err error) (string, bool) {
	switch {
	case errors.Is(err, ErrAccess):
		return "access_revoked", false
	case errors.Is(err, ErrRejected):
		return "content_rejected", false
	case errors.Is(err, ErrIntegrity), errors.Is(err, ErrInvalid):
		return "integrity_mismatch", false
	case errors.Is(err, ErrScanUnavailable):
		return "scan_unavailable", true
	default:
		return "storage_unavailable", true
	}
}

func (service *Service) DeleteNext(ctx context.Context) (bool, error) {
	attempt, cancel := context.WithTimeout(ctx, 2*time.Second)
	claim, err := service.repository.ClaimDeletion(attempt)
	cancel()
	if err != nil || claim == nil {
		return false, err
	}
	key, err := claim.Key()
	if err != nil {
		return true, ErrInvalid
	}
	until := min(time.Now().Add(10*time.Second).UnixNano(), claim.LeaseUntil.Add(-100*time.Millisecond).UnixNano())
	remove, stop := context.WithDeadline(ctx, time.Unix(0, until))
	err = service.storage.Delete(remove, key)
	stop()
	if ctx.Err() != nil {
		return true, ctx.Err()
	}
	record, closeRecord := context.WithTimeout(context.Background(), 2*time.Second)
	defer closeRecord()
	if failure := service.repository.CompleteDeletion(record, *claim, err == nil); failure != nil {
		return true, failure
	}
	return true, err
}
