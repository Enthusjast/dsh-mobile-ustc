package files

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

type ExportRepository interface {
	RegisterExport(context.Context, Actor, HostBinding, ExportRegistration) (Record, error)
	AuthorizeExportUpload(context.Context, Actor, HostBinding, string) (Record, error)
	BeginExportScan(context.Context, Actor, HostBinding, string) (Record, error)
	AuthorizeExportDownload(context.Context, Actor, string, string) (DownloadPermit, error)
	AuditExportDownload(context.Context, Actor, DownloadPermit, string, string) error
	ExportStatusByRequest(context.Context, Actor, string) (Record, error)
}
type ExportBlobStore interface {
	BlobStore
	PresignHostExport(context.Context, ObjectKey, int64, string, time.Duration) (UploadURL, error)
}

type Exports struct {
	repository ExportRepository
	storage    ExportBlobStore
	service    *Service
	mu         sync.Mutex
	active     map[string]int
	count      int
	lifetime   context.Context
	stop       context.CancelFunc
}

func NewExports(repository ExportRepository, storage ExportBlobStore, service *Service) (*Exports, error) {
	if repository == nil || storage == nil || service == nil {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Exports{repository: repository, storage: storage, service: service, active: make(map[string]int), lifetime: ctx, stop: cancel}, nil
}
func (controller *Exports) Close() { controller.stop() }
func (controller *Exports) Status(ctx context.Context, actor Actor, request string) (Status, error) {
	record, err := controller.repository.ExportStatusByRequest(ctx, actor, request)
	return record.Status(), err
}
func (controller *Exports) Register(ctx context.Context, actor Actor, host HostBinding, input ExportRegistration) (UploadPrepared, error) {
	if controller.lifetime.Err() != nil {
		return UploadPrepared{}, ErrUnavailable
	}
	if !controller.service.Ready() {
		return UploadPrepared{}, ErrScanUnavailable
	}
	record, err := controller.repository.RegisterExport(ctx, actor, host, input)
	if err != nil {
		return UploadPrepared{}, err
	}
	if record.Direction != "from_host" {
		return UploadPrepared{}, ErrAccess
	}
	if record.State != "uploading" {
		return UploadPrepared{File: record.Status()}, nil
	}
	return controller.Upload(ctx, actor, host, record.ID)
}
func (controller *Exports) Upload(ctx context.Context, actor Actor, host HostBinding, id string) (UploadPrepared, error) {
	if controller.lifetime.Err() != nil {
		return UploadPrepared{}, ErrUnavailable
	}
	if !controller.service.Ready() {
		return UploadPrepared{}, ErrScanUnavailable
	}
	record, err := controller.repository.AuthorizeExportUpload(ctx, actor, host, id)
	if err != nil {
		return UploadPrepared{}, err
	}
	if record.Direction != "from_host" || record.State != "uploading" {
		return UploadPrepared{}, ErrAccess
	}
	key, err := record.SourceKey()
	if err != nil {
		return UploadPrepared{}, ErrUnavailable
	}
	ttl := min(time.Until(uploadDeadline(record)).Truncate(time.Second), 5*time.Minute)
	if ttl < time.Second {
		return UploadPrepared{}, ErrStale
	}
	capability, err := controller.storage.PresignHostExport(ctx, key, record.SizeBytes, record.SHA256, ttl)
	if err != nil {
		return UploadPrepared{}, err
	}
	if ctx.Err() != nil || controller.lifetime.Err() != nil {
		return UploadPrepared{}, ErrAccess
	}
	if !currentUploadCapability(record, capability) {
		return UploadPrepared{}, ErrStale
	}
	return UploadPrepared{File: record.Status(), Upload: &capability}, nil
}
func (controller *Exports) Commit(ctx context.Context, actor Actor, host HostBinding, id string) (Status, error) {
	if controller.lifetime.Err() != nil {
		return Status{}, ErrUnavailable
	}
	if !controller.service.Ready() {
		return Status{}, ErrScanUnavailable
	}
	record, err := controller.repository.BeginExportScan(ctx, actor, host, id)
	return record.Status(), err
}

func (controller *Exports) acquire(device string) (func(), error) {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.lifetime.Err() != nil {
		return nil, ErrUnavailable
	}
	if controller.count >= 64 || controller.active[device] >= 2 {
		return nil, ErrQuota
	}
	controller.count++
	controller.active[device]++
	return func() {
		controller.mu.Lock()
		defer controller.mu.Unlock()
		controller.count--
		controller.active[device]--
		if controller.active[device] == 0 {
			delete(controller.active, device)
		}
	}, nil
}

type ExportRead struct {
	File     Status
	ctx      context.Context
	cancel   context.CancelFunc
	body     io.ReadCloser
	verified *VerifiedReader
	done     chan struct{}
	complete atomic.Bool
	eof      atomic.Bool
	failed   atomic.Bool
	once     sync.Once
	finish   func(string) error
	release  func()
}

func (read *ExportRead) Context() context.Context { return read.ctx }
func (read *ExportRead) Read(target []byte) (int, error) {
	if read.ctx.Err() != nil {
		return 0, read.ctx.Err()
	}
	n, err := read.verified.Read(target[:min(len(target), ChunkBytes)])
	if read.ctx.Err() != nil {
		return 0, read.ctx.Err()
	}
	if err == io.EOF {
		read.eof.Store(true)
	} else if err != nil {
		read.failed.Store(true)
	}
	return n, err
}

// Complete records only that the server verified and served the full response;
// the receiving phone still verifies its own saved bytes independently.
func (read *ExportRead) Complete() error {
	if !read.eof.Load() || read.failed.Load() || read.ctx.Err() != nil {
		return ErrIntegrity
	}
	read.complete.Store(true)
	return nil
}
func (read *ExportRead) Close() error {
	var result error
	read.once.Do(func() {
		outcome := "cancelled"
		if read.complete.Load() {
			outcome = "served"
		} else if read.failed.Load() {
			outcome = "failed"
		}
		read.cancel()
		if read.body != nil {
			_ = read.body.Close()
		}
		<-read.done
		result = read.finish(outcome)
		read.release()
	})
	return result
}

func (controller *Exports) Open(parent context.Context, actor Actor, id string) (*ExportRead, error) {
	if !objectUUID.MatchString(actor.DeviceID) || !objectUUID.MatchString(id) {
		return nil, ErrAccess
	}
	release, err := controller.acquire(actor.DeviceID)
	if err != nil {
		return nil, err
	}
	accepted := false
	defer func() {
		if !accepted {
			release()
		}
	}()
	permit, err := controller.repository.AuthorizeExportDownload(parent, actor, id, controller.service.config.PolicySHA256)
	if err != nil {
		return nil, err
	}
	if permit.File.Direction != "from_host" || permit.File.State != "clean" || !permit.LeaseUntil.After(time.Now()) {
		return nil, ErrAccess
	}
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return nil, ErrUnavailable
	}
	request := hex.EncodeToString(entropy[:])
	if err := controller.repository.AuditExportDownload(parent, actor, permit, request, "opened"); err != nil {
		return nil, err
	}
	if parent.Err() != nil || controller.lifetime.Err() != nil || !permit.LeaseUntil.After(time.Now()) || !permit.File.ExpiresAt.After(time.Now()) {
		return nil, ErrAccess
	}
	ctx, deadline := context.WithDeadline(parent, minTime(permit.File.ExpiresAt, time.Now().Add(5*time.Minute)))
	ctx, stop := context.WithCancel(ctx)
	detach := context.AfterFunc(controller.lifetime, stop)
	read := &ExportRead{File: permit.File.Status(), ctx: ctx, cancel: func() { stop(); deadline(); detach() }, done: make(chan struct{}), release: release,
		finish: func(outcome string) error {
			audit, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			return controller.repository.AuditExportDownload(audit, actor, permit, request, outcome)
		}}
	go func() {
		defer close(read.done)
		defer stop()
		// Cancellation runs independently of a blocked metadata renewal. A
		// slow database cannot keep object headers/body alive past this lease.
		lease := time.AfterFunc(max(0, time.Until(permit.LeaseUntil)-100*time.Millisecond), stop)
		defer lease.Stop()
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				check, cancel := context.WithTimeout(ctx, time.Second)
				current, err := controller.repository.AuthorizeExportDownload(check, actor, id, controller.service.config.PolicySHA256)
				cancel()
				if err != nil || current.AuthorizedGrantVersion != permit.AuthorizedGrantVersion || current.File.RequestSHA256 != permit.File.RequestSHA256 || current.File.CommittedAttempt != permit.File.CommittedAttempt ||
					current.File.SizeBytes != permit.File.SizeBytes || current.File.SHA256 != permit.File.SHA256 || current.File.Direction != "from_host" || !current.LeaseUntil.After(time.Now()) {
					return
				}
				if !lease.Stop() || ctx.Err() != nil {
					return
				}
				lease.Reset(max(0, time.Until(current.LeaseUntil)-100*time.Millisecond))
			}
		}
	}()
	key, err := permit.File.CommittedKey()
	if err == nil {
		read.body, err = controller.storage.OpenEncrypted(ctx, key, permit.File.SizeBytes)
	}
	if err == nil {
		context.AfterFunc(ctx, func() { _ = read.body.Close() })
		read.verified, err = newDownloadVerifier(read.body, permit.File.SizeBytes, permit.File.SHA256)
	}
	if err != nil || ctx.Err() != nil {
		read.failed.Store(err != nil && ctx.Err() == nil)
		accepted = true // Close owns the one release after audit/lease teardown.
		_ = read.Close()
		if err == nil {
			err = ErrAccess
		}
		return nil, err
	}
	accepted = true
	return read, nil
}

func minTime(first, second time.Time) time.Time {
	if second.Before(first) {
		return second
	}
	return first
}
