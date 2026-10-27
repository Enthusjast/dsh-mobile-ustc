package httpapi_test

import (
	"io"
	"testing"

	"dsh-mobile-ustc/services/remote/internal/store"
)

func TestRecoveryQuarantineInvalidatesStagedFileAndItsSingleUseRead(t *testing.T) {
	h := newFileHTTPFixture(t)
	body := []byte("bounded recovery file fixture")
	h.cleanForHandoff(t, body)
	host := connectFileHost(t, h)
	offer := host.offer(t)
	response, err := host.download(t, offer, host.key)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != 200 {
		t.Fatal("fixture did not read file", err)
	}
	host.send(t, map[string]any{"v": 1, "type": "file.staged", "request_id": capacityID(), "runtime_id": fileRuntimeID, "runtime_epoch": host.epoch, "session_id": h.session, "payload": map[string]any{"handoff_id": offer.HandoffID, "file_id": offer.FileID, "sha256": offer.SHA256, "size_bytes": offer.SizeBytes, "name": offer.Name}})
	if frame := host.read(t); string(frame["type"]) != `"file.staged.ack"` {
		t.Fatal("fixture did not stage file")
	}
	if _, err := (&store.Postgres{DB: h.database}).QuarantineRecovery(h.ctx, capacityID(), store.OriginalDatabaseEpoch, capacityID()); err != nil {
		t.Fatal(err)
	}
	var state string
	var name *string
	if err := h.database.QueryRowContext(h.ctx, `select state,staged_name from file_handoffs where id=$1`, offer.HandoffID).Scan(&state, &name); err != nil || state != "invalidated" || name != nil {
		t.Fatal("staged attachment remained usable", state, err)
	}
	rejected, err := host.download(t, offer, host.key)
	if err != nil {
		t.Fatal(err)
	}
	defer rejected.Body.Close()
	if rejected.StatusCode != 403 {
		t.Fatal("old file ticket survived quarantine", rejected.StatusCode)
	}
}
