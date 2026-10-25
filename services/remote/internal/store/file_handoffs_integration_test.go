package store

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/files"
)

type handoffFixture struct {
	*fileFixture
	host   files.HostBinding
	file   files.Record
	public []byte
	key    *ecdsa.PrivateKey
}

func TestPostgresHandoffReadTicketHasOneConcurrentWinner(t *testing.T) {
	h := newHandoffFixture(t)
	offer := h.offer(t)
	if _, err := h.repository.RedeemFileRead(h.ctx, offer.HandoffID, offer.DownloadToken, fileTestPolicy, nil); !errors.Is(err, files.ErrAccess) {
		t.Fatal("nil proof verifier consumed ticket")
	}
	var winners atomic.Int32
	var callers sync.WaitGroup
	for i := 0; i < 8; i++ {
		callers.Go(func() {
			_, err := h.repository.RedeemFileRead(h.ctx, offer.HandoffID, offer.DownloadToken, fileTestPolicy, func(files.ReadPermit) error { return nil })
			if err == nil {
				winners.Add(1)
			} else if !errors.Is(err, files.ErrAccess) {
				t.Error(err)
			}
		})
	}
	callers.Wait()
	if winners.Load() != 1 {
		t.Fatalf("concurrent winners=%d", winners.Load())
	}
	var audit int
	if err := h.database.DB.QueryRowContext(h.ctx, `select count(*) from audit_log where action='file.host_read' and actor_type='installation' and metadata->>'handoff_id'=$1`, offer.HandoffID).Scan(&audit); err != nil || audit != 1 {
		t.Fatal("read audit was not atomic with ticket redemption")
	}
}

func newHandoffFixture(t *testing.T) *handoffFixture {
	t.Helper()
	h := newFileFixture(t)
	file := h.scanning(t)
	claim := h.claim(t)
	if err := h.repository.CompleteScan(h.ctx, claim); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := integrationP256JWK(key)
	if err != nil {
		t.Fatal(err)
	}
	thumb, err := auth.PublicP256JWKThumbprintJSON(public)
	if err != nil {
		t.Fatal(err)
	}
	h.exec(t, `update installations set public_jwk=$1,public_key_thumbprint=$2`, public, thumb)
	connection, err := h.database.AttachRuntimeConnection(h.ctx, RuntimeConnectionInput{InstallationID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", KeyVersion: 1, RuntimeID: h.input.RuntimeID, RuntimeEpoch: approvalTestUUID(t), ConnectionID: approvalTestUUID(t), DSHVersion: "0.2.1-rc.2", ApplicationVersion: "file-handoff-fixture", PluginVersion: "test", ProtocolVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	// File ID and Session ID are separate identities.
	h.exec(t, `update sessions set state='available' where id=$1`, file.SessionID)
	return &handoffFixture{fileFixture: h, file: file, key: key, public: public, host: files.HostBinding{InstallationID: connection.InstallationID, KeyVersion: 1, RuntimeID: connection.RuntimeID, RuntimeEpoch: connection.RuntimeEpoch, ConnectionID: connection.ConnectionID, CredentialExpiresAt: time.Now().Add(5 * time.Minute)}}
}
func (h *handoffFixture) offer(t *testing.T) *files.FileOffer {
	t.Helper()
	offer, err := h.repository.IssueHandoff(h.ctx, h.host, h.file.ID, fileTestPolicy)
	if err != nil || offer == nil {
		t.Fatalf("offer=%v error=%v", offer, err)
	}
	return offer
}

func TestPostgresHandoffTicketIsOneUseAndInvalidProofDoesNotConsumeIt(t *testing.T) {
	h := newHandoffFixture(t)
	offer := h.offer(t)
	if again, err := h.repository.IssueHandoff(h.ctx, h.host, h.file.ID, fileTestPolicy); err != nil || again != nil {
		t.Fatal("live handoff issued a second secret")
	}
	if _, err := h.repository.RedeemFileRead(h.ctx, offer.HandoffID, offer.DownloadToken, fileTestPolicy, func(files.ReadPermit) error { return errors.New("bad signature") }); !errors.Is(err, files.ErrAccess) {
		t.Fatal("invalid signature consumed download")
	}
	if _, err := h.repository.RedeemFileRead(h.ctx, offer.HandoffID, strings.Repeat("A", 43), fileTestPolicy, func(files.ReadPermit) error { return nil }); !errors.Is(err, files.ErrAccess) {
		t.Fatal("wrong token was accepted")
	}
	permit, err := h.repository.RedeemFileRead(h.ctx, offer.HandoffID, offer.DownloadToken, fileTestPolicy, func(permit files.ReadPermit) error {
		if string(permit.PublicJWK) != string(h.public) {
			var a, b any
			_ = json.Unmarshal(permit.PublicJWK, &a)
			_ = json.Unmarshal(h.public, &b)
			if !reflect.DeepEqual(a, b) {
				return errors.New("bad key")
			}
		}
		return nil
	})
	if err != nil || permit.Handoff.State != "downloading" {
		t.Fatalf("redemption=%v", err)
	}
	if _, err := h.repository.RedeemFileRead(h.ctx, offer.HandoffID, offer.DownloadToken, fileTestPolicy, func(files.ReadPermit) error { return nil }); !errors.Is(err, files.ErrAccess) {
		t.Fatal("read token replay succeeded")
	}
	if _, err := h.repository.RenewHandoff(h.ctx, h.host, offer.HandoffID, fileTestPolicy); err != nil {
		t.Fatal(err)
	}
	if _, err := h.repository.CheckFileRead(h.ctx, h.host, offer.HandoffID, fileTestPolicy); err != nil {
		t.Fatal(err)
	}
	if err := h.repository.StageHandoff(h.ctx, h.host, offer.HandoffID, h.file.SHA256, h.file.SizeBytes, "normalized.txt", fileTestPolicy); err != nil {
		t.Fatal(err)
	}
	if err := h.repository.StageHandoff(h.ctx, h.host, offer.HandoffID, h.file.SHA256, h.file.SizeBytes, "normalized.txt", fileTestPolicy); err != nil {
		t.Fatal(err)
	}
	var staged, events int
	if err := h.database.DB.QueryRowContext(h.ctx, `select (select count(*) from audit_log where action='file.host_staged'),(select count(*) from control_outbox where topic='file.clean' and published_at is not null)`).Scan(&staged, &events); err != nil || staged != 1 || events != 1 {
		t.Fatal("stage acknowledgement was not durable/idempotent")
	}
	if err := h.repository.EndHandoff(h.ctx, h.host, offer.HandoffID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.repository.CheckFileRead(h.ctx, h.host, offer.HandoffID, fileTestPolicy); !errors.Is(err, files.ErrStale) {
		t.Fatal("ended authority remained usable")
	}
}

func TestPostgresHandoffFencesEpochAuthorizationAndScanPolicy(t *testing.T) {
	h := newHandoffFixture(t)
	offer := h.offer(t)
	wrong := h.host
	wrong.ConnectionID = approvalTestUUID(t)
	if _, err := h.repository.RenewHandoff(h.ctx, wrong, offer.HandoffID, fileTestPolicy); !errors.Is(err, files.ErrAccess) {
		t.Fatal("foreign connection renewed file authority")
	}
	h.exec(t, `update file_handoffs set lease_until=clock_timestamp()-interval '1 second' where id=$1`, offer.HandoffID)
	if _, err := h.repository.RenewHandoff(h.ctx, h.host, offer.HandoffID, fileTestPolicy); !errors.Is(err, files.ErrStale) {
		t.Fatal("expired handoff revived")
	}
	fresh := h.offer(t)
	if fresh.HandoffID == offer.HandoffID || fresh.DownloadToken == offer.DownloadToken {
		t.Fatal("restaging reused old identity")
	}
	h.exec(t, `update runtime_grants set grant_version=grant_version+1`)
	if pending, err := h.repository.PendingHandoffFiles(h.ctx, h.host, fileTestPolicy, 2); err != nil || len(pending) != 0 {
		t.Fatal("revoked uploader remained a pending candidate")
	}
	if _, err := h.repository.RenewHandoff(h.ctx, h.host, fresh.HandoffID, fileTestPolicy); !errors.Is(err, files.ErrAccess) {
		t.Fatal("revoked uploader authority renewed")
	}
	h.exec(t, `update runtime_grants set grant_version=grant_version-1`)
	if _, err := h.repository.RenewHandoff(h.ctx, h.host, fresh.HandoffID, strings.Repeat("b", 64)); !errors.Is(err, files.ErrAccess) {
		t.Fatal("different scanner policy became trusted")
	}
	h.exec(t, `update sessions set state='archived'`)
	if _, err := h.repository.RenewHandoff(h.ctx, h.host, fresh.HandoffID, fileTestPolicy); !errors.Is(err, files.ErrAccess) {
		t.Fatal("archived session retained incoming file authority")
	}
	h.exec(t, `update sessions set state='available'`)
	h.exec(t, `update runtimes set epoch=$1`, approvalTestUUID(t))
	if _, err := h.repository.RenewHandoff(h.ctx, h.host, fresh.HandoffID, fileTestPolicy); !errors.Is(err, files.ErrAccess) {
		t.Fatal("old runtime epoch remained trusted")
	}
}
