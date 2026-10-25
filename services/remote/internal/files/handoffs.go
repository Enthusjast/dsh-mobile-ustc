package files

import (
	"context"
	"io"
	"sync"
	"time"
)

type Handoffs struct {
	repository HandoffRepository
	storage    BlobStore
	policy     string
}

func (controller *Handoffs) PolicySHA256() string { return controller.policy }
func (controller *Handoffs) MessageReference(ctx context.Context, id string) (*Delivery, error) {
	return controller.repository.FileMessageReference(ctx, id)
}

func NewHandoffs(repository HandoffRepository, storage BlobStore, policy string) (*Handoffs, error) {
	if repository == nil || storage == nil {
		return nil, ErrInvalid
	}
	if _, valid := checksum(policy); !valid {
		return nil, ErrInvalid
	}
	return &Handoffs{repository: repository, storage: storage, policy: policy}, nil
}
func (controller *Handoffs) Offer(ctx context.Context, host HostBinding, file string) (*FileOffer, error) {
	return controller.repository.IssueHandoff(ctx, host, file, controller.policy)
}
func (controller *Handoffs) Pending(ctx context.Context, host HostBinding, limit int) ([]string, error) {
	return controller.repository.PendingHandoffFiles(ctx, host, controller.policy, limit)
}
func (controller *Handoffs) Renew(ctx context.Context, host HostBinding, id string) (Handoff, error) {
	return controller.repository.RenewHandoff(ctx, host, id, controller.policy)
}
func (controller *Handoffs) Staged(ctx context.Context, host HostBinding, id, sha string, size int64, name string) error {
	return controller.repository.StageHandoff(ctx, host, id, sha, size, name, controller.policy)
}
func (controller *Handoffs) End(ctx context.Context, host HostBinding, id string) error {
	return controller.repository.EndHandoff(ctx, host, id)
}

type FileRead struct {
	Handoff Handoff
	body    io.ReadCloser
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}
	once    sync.Once
}

func (read *FileRead) Read(target []byte) (int, error) {
	if read.ctx.Err() != nil {
		return 0, read.ctx.Err()
	}
	return read.body.Read(target[:min(len(target), ChunkBytes)])
}
func (read *FileRead) Close() error {
	read.once.Do(func() { read.cancel(); _ = read.body.Close(); <-read.done })
	return nil
}

// Open consumes a sender-constrained ticket only after verify succeeds. The
// host lifetime and periodically renewed database authority both own the body.
func (controller *Handoffs) Open(parent context.Context, id, token string, verify func(ReadPermit) error, live func(HostBinding) (<-chan struct{}, error)) (*FileRead, error) {
	var hostDone <-chan struct{}
	permit, err := controller.repository.RedeemFileRead(parent, id, token, controller.policy, func(permit ReadPermit) error {
		if verify == nil || live == nil {
			return ErrAccess
		}
		if err := verify(permit); err != nil {
			return err
		}
		var err error
		hostDone, err = live(permit.Handoff.Host)
		return err
	})
	if err != nil {
		return nil, err
	}
	ctx, closeDeadline := context.WithDeadline(parent, permit.Handoff.ExpiresAt)
	ctx, cancel := context.WithCancel(ctx)
	key, err := permit.Handoff.File.CommittedKey()
	if err != nil {
		cancel()
		closeDeadline()
		return nil, ErrUnavailable
	}
	read := &FileRead{Handoff: permit.Handoff, ctx: ctx, cancel: func() { cancel(); closeDeadline() }, done: make(chan struct{})}
	go func() {
		defer close(read.done)
		defer cancel()
		lease := time.NewTimer(max(0, time.Until(permit.Handoff.LeaseUntil)-100*time.Millisecond))
		defer lease.Stop()
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-hostDone:
				return
			case <-lease.C:
				return
			case <-ticker.C:
				if _, err := live(permit.Handoff.Host); err != nil {
					return
				}
				attempt, closeAttempt := context.WithTimeout(ctx, time.Second)
				handoff, err := controller.repository.CheckFileRead(attempt, permit.Handoff.Host, id, controller.policy)
				closeAttempt()
				if err != nil {
					return
				}
				if !lease.Stop() {
					select {
					case <-lease.C:
					default:
					}
				}
				lease.Reset(max(0, time.Until(handoff.LeaseUntil)-100*time.Millisecond))
			}
		}
	}()
	body, err := controller.storage.OpenEncrypted(ctx, key, permit.Handoff.File.SizeBytes)
	if err != nil {
		read.cancel()
		<-read.done
		return nil, err
	}
	if ctx.Err() != nil {
		_ = body.Close()
		read.cancel()
		<-read.done
		return nil, ErrAccess
	}
	read.body = body
	context.AfterFunc(ctx, func() { _ = body.Close() })
	return read, nil
}
