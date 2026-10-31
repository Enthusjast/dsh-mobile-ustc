package httpapi_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"image/png"
	"io"
	"net/http"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/files"
)

// This reader only obtains image references from the ordinary, visibility-filtered
// native transcript. Neither the phone nor this fixture supplies attachment IDs.
type nativeImageReader struct {
	phone                     *fileHost
	epoch, subscription, sync string
	reference                 json.RawMessage
}

func subscribeNativeImage(t *testing.T, phone *fileHost) nativeImageReader {
	t.Helper()
	reader := nativeImageReader{phone: phone}
	phone.send(t, map[string]any{"v": 1, "type": "session.subscribe", "request_id": exportTestUUID(t), "runtime_id": fileRuntimeID, "session_id": phone.fixture.session, "payload": map[string]any{"max_messages": 30}})
	for {
		frame := phone.read(t)
		switch string(frame["type"]) {
		case `"session.subscribed"`:
			_ = json.Unmarshal(frame["runtime_epoch"], &reader.epoch)
			_ = json.Unmarshal(frame["subscription_id"], &reader.subscription)
		case `"session.snapshot"`:
			_ = json.Unmarshal(frame["sync_id"], &reader.sync)
			var payload struct {
				Records []struct {
					Type string `json:"type"`
					Data struct {
						Content []struct {
							Type      string          `json:"type"`
							Reference json.RawMessage `json:"reference"`
						} `json:"content"`
					} `json:"data"`
				} `json:"records"`
			}
			if json.Unmarshal(frame["payload"], &payload) != nil {
				t.Fatal("invalid native snapshot")
			}
			for _, record := range payload.Records {
				if record.Type != "user/message" {
					continue
				}
				for _, part := range record.Data.Content {
					if part.Type == "image" {
						reader.reference = part.Reference
					}
				}
			}
		case `"session.checkpoint"`:
			var checkpoint struct {
				State string `json:"state"`
			}
			_ = json.Unmarshal(frame["payload"], &checkpoint)
			if checkpoint.State != "persisted" || reader.epoch == "" || reader.subscription == "" || reader.sync == "" || len(reader.reference) == 0 {
				t.Fatal("typed native image reader lacks persisted current reference")
			}
			return reader
		default:
			t.Fatalf("unexpected native reader frame: %s", frame["type"])
		}
	}
}

func imageReply(t *testing.T, phone *fileHost, request string) map[string]json.RawMessage {
	t.Helper()
	for {
		frame := phone.read(t)
		var id string
		_ = json.Unmarshal(frame["request_id"], &id)
		if id == request {
			return frame
		}
		if string(frame["type"]) != `"session.error"` {
			t.Fatalf("unexpected image reply: %s", frame["type"])
		}
	}
}

func (reader nativeImageReader) resolve(t *testing.T, phone *fileHost, session, sync string) map[string]json.RawMessage {
	t.Helper()
	request := exportTestUUID(t)
	phone.send(t, map[string]any{"v": 1, "type": "session.media.resolve", "request_id": request, "runtime_id": fileRuntimeID,
		"runtime_epoch": reader.epoch, "session_id": session, "subscription_id": reader.subscription,
		"payload": map[string]any{"sync_id": sync, "reference": reader.reference}})
	return imageReply(t, phone, request)
}

func imageDenied(t *testing.T, frame map[string]json.RawMessage, expected string) {
	t.Helper()
	var payload struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(frame["payload"], &payload)
	kind := string(frame["type"])
	if (kind != `"error"` && kind != `"session.media.error"` && kind != `"session.error"` && kind != `"file.export.error"`) || payload.Code != expected {
		t.Fatalf("image denial type=%s code=%s, expected=%s", kind, payload.Code, expected)
	}
}

func imageAuthorityRows(t *testing.T, h *fileHTTPFixture) [2]int {
	t.Helper()
	var rows [2]int
	if err := h.database.QueryRowContext(h.ctx, `select (select count(*) from files),(select count(*) from file_exports)`).Scan(&rows[0], &rows[1]); err != nil {
		t.Fatal(err)
	}
	return rows
}

func exerciseNativeImageExport(t *testing.T, h *fileHTTPFixture, epoch, expectedSHA string) {
	t.Helper()
	const device = "33333333-3333-4333-8333-333333333333"
	const secondDevice = "88888888-8888-4888-8888-888888888888"
	const grantPath = "/v1/runtimes/" + fileRuntimeID + "/grants/22222222-2222-4222-8222-222222222222"
	// Only this disposable fixture gets organization grant administration. Actual
	// grant transitions below use the authenticated API, transaction and outbox.
	if _, err := h.database.ExecContext(h.ctx, `update org_memberships set role='admin' where user_id='22222222-2222-4222-8222-222222222222'`); err != nil {
		t.Fatal(err)
	}
	changeGrant := func(download bool) {
		t.Helper()
		actions := []string{"session.read", "grant.manage"}
		if download {
			actions = append(actions, "file.download", "file.upload")
		}
		code, _ := h.caller.call(h.token, "PUT", grantPath, map[string]any{"role": "owner", "scope": map[string]any{"actions": actions, "workspaces": []string{fileWorkspaceID}, "sessions": []string{h.session}}})
		if code != 200 {
			t.Fatalf("authoritative image grant change=%d", code)
		}
	}
	changeGrant(false)
	readOnly := connectExportPhoneScope(t, h, h.caller, h.token, device, false, true, false)
	readOnlyReader := subscribeNativeImage(t, readOnly)
	before := imageAuthorityRows(t, h)
	imageDenied(t, readOnlyReader.resolve(t, readOnly, h.session, readOnlyReader.sync), "access.denied")
	if imageAuthorityRows(t, h) != before {
		t.Fatal("read-only refusal minted image export authority")
	}
	changeGrant(true)
	phone := connectExportPhoneScope(t, h, h.caller, h.token, device, false, true, true)
	reader := subscribeNativeImage(t, phone)
	var reference struct {
		Version  int    `json:"v"`
		Origin   string `json:"origin"`
		Manifest struct {
			SHA  string `json:"sha256"`
			Size int64  `json:"size_bytes"`
		} `json:"manifest"`
		MediaType     string `json:"media_type"`
		Width, Height int
	}
	if json.Unmarshal(reader.reference, &reference) != nil || reference.Version != 1 || reference.Origin != "session_attachment" || reference.Manifest.SHA != expectedSHA || reference.MediaType != "image/png" || reference.Width != 1 || reference.Height != 1 {
		t.Fatal("native image reference changed manifest or raster facts")
	}
	before = imageAuthorityRows(t, h)
	imageDenied(t, reader.resolve(t, phone, h.session, exportTestUUID(t)), "protocol.resync_required")
	imageDenied(t, reader.resolve(t, phone, exportTestUUID(t), reader.sync), "protocol.resync_required")
	other := connectExportPhoneScope(t, h, h.second, h.secondToken, secondDevice, false, true, true)
	imageDenied(t, reader.resolve(t, other, h.session, reader.sync), "protocol.resync_required")
	if imageAuthorityRows(t, h) != before {
		t.Fatal("foreign session/device or stale sync minted authority")
	}
	resolved := reader.resolve(t, phone, h.session, reader.sync)
	var result struct {
		Reference json.RawMessage  `json:"reference"`
		Source    nativeExportNode `json:"source"`
	}
	if string(resolved["type"]) != `"session.media.result"` || json.Unmarshal(resolved["payload"], &result) != nil || result.Source.Origin != "session_attachment" || result.Source.Kind != "file" || result.Source.ID == "" {
		var failure struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(resolved["payload"], &failure)
		t.Fatalf("native media did not resolve through Relay: type=%s code=%s", resolved["type"], failure.Code)
	}
	var original, returned any
	_ = json.Unmarshal(reader.reference, &original)
	_ = json.Unmarshal(result.Reference, &returned)
	originalJSON, _ := json.Marshal(original)
	returnedJSON, _ := json.Marshal(returned)
	if !bytes.Equal(originalJSON, returnedJSON) {
		t.Fatal("resolved media reference differs from visible reference")
	}
	imageDenied(t, requestNativeExport(t, other, epoch, exportTestUUID(t), result.Source.ID), "file.export_unavailable")
	if imageAuthorityRows(t, h) != before {
		t.Fatal("foreign image source minted export authority")
	}
	request := exportTestUUID(t)
	accepted := requestNativeExport(t, phone, epoch, request, result.Source.ID)
	var exported struct {
		File files.Status `json:"file"`
	}
	if string(accepted["type"]) != `"file.export.accepted"` || json.Unmarshal(accepted["payload"], &exported) != nil || exported.File.SHA256 != expectedSHA || exported.File.SizeBytes != reference.Manifest.Size {
		t.Fatal("exact native image export failed")
	}
	for deadline := time.Now().Add(5 * time.Second); ; {
		status := h.status(t, exported.File.ID)
		if status.State == "clean" {
			break
		}
		if status.State == "rejected" || time.Now().After(deadline) {
			t.Fatal("native image did not scan clean")
		}
		time.Sleep(20 * time.Millisecond)
	}
	response, err := h.caller.content(h.token, "/v1/files/"+exported.File.ID+"/content", h.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != 200 || response.Header.Get("Cache-Control") != "no-store, no-transform" {
		t.Fatal("protected native image download failed")
	}
	sha := sha256.Sum256(data)
	if hex.EncodeToString(sha[:]) != expectedSHA || response.Header.Get("X-DSH-Content-SHA256") != expectedSHA || http.DetectContentType(data) != reference.MediaType {
		t.Fatal("protected image digest or MIME mismatch")
	}
	decoded, err := png.Decode(bytes.NewReader(data))
	if err != nil || decoded.Bounds().Dx() != reference.Width || decoded.Bounds().Dy() != reference.Height {
		t.Fatal("protected image raster mismatch")
	}
	// HTTP content is independently authorized; removing download from the
	// actual grant must refuse this SAME image, not just a narrow relay ticket.
	changeGrant(false)
	readOnly = connectExportPhoneScope(t, h, h.caller, h.token, device, false, true, false)
	readOnlyReader = subscribeNativeImage(t, readOnly)
	before = imageAuthorityRows(t, h)
	imageDenied(t, readOnlyReader.resolve(t, readOnly, h.session, readOnlyReader.sync), "access.denied")
	response, err = h.caller.content(h.token, "/v1/files/"+exported.File.ID+"/content", h.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatalf("same image read-only protected content=%d", response.StatusCode)
	}
	if imageAuthorityRows(t, h) != before {
		t.Fatal("same image read-only refusal minted authority")
	}
	changeGrant(true)
	phone = connectExportPhoneScope(t, h, h.caller, h.token, device, false, true, true)
	reader = subscribeNativeImage(t, phone)
	resolved = reader.resolve(t, phone, h.session, reader.sync)
	if string(resolved["type"]) != `"session.media.result"` || json.Unmarshal(resolved["payload"], &result) != nil {
		t.Fatal("restored grant could not resolve same image")
	}
	// SAME scanned image, with its object response held before headers. These
	// channels have not been used by the earlier unblocked scanner/download GETs.
	h.peer.mu.Lock()
	h.peer.blockHeaders = true
	h.peer.mu.Unlock()
	downloadCtx, cancel := context.WithTimeout(h.ctx, 8*time.Second)
	defer cancel()
	worker := *h.caller
	type outcome struct {
		response *http.Response
		err      error
	}
	done := make(chan outcome, 1)
	go func() {
		response, err := worker.content(h.token, "/v1/files/"+exported.File.ID+"/content", downloadCtx, nil)
		done <- outcome{response, err}
	}()
	select {
	case <-h.peer.getStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("same image download did not await object headers")
	}
	code, _ := h.caller.call(h.token, "DELETE", grantPath, nil)
	if code != 200 {
		t.Fatalf("authoritative image grant revoke=%d", code)
	}
	select {
	case result := <-done:
		if result.response != nil {
			_ = result.response.Body.Close()
			if result.response.StatusCode == 200 {
				t.Fatal("revoked image received headers")
			}
		}
	case <-time.After(3 * time.Second):
		t.Fatal("grant revoke did not cancel same-image pending headers")
	}
	select {
	case <-h.peer.getCancelled:
	case <-time.After(time.Second):
		t.Fatal("revoked image upstream remained active")
	}
	before = imageAuthorityRows(t, h)
	// The old connection may be authoritatively closed before a reply; that is a
	// refusal too. Read it directly rather than weakening the ordinary helper.
	for _, frame := range []map[string]any{
		{"v": 1, "type": "session.media.resolve", "request_id": exportTestUUID(t), "runtime_id": fileRuntimeID, "runtime_epoch": reader.epoch, "session_id": h.session, "subscription_id": reader.subscription, "payload": map[string]any{"sync_id": reader.sync, "reference": reader.reference}},
		{"v": 1, "type": "file.export.request", "request_id": exportTestUUID(t), "runtime_id": fileRuntimeID, "runtime_epoch": reader.epoch, "session_id": h.session, "payload": map[string]any{"source_id": result.Source.ID}},
	} {
		raw, _ := json.Marshal(frame)
		if err := phone.connection.Write(h.ctx, 1, raw); err != nil {
			continue
		}
		readCtx, readCancel := context.WithTimeout(h.ctx, 3*time.Second)
		_, reply, err := phone.connection.Read(readCtx)
		readCancel()
		if err == nil {
			var denied map[string]json.RawMessage
			_ = json.Unmarshal(reply, &denied)
			kind := string(denied["type"])
			if kind != `"error"` && kind != `"session.error"` && kind != `"session.media.error"` && kind != `"file.export.error"` {
				t.Fatal("revoked reader/source remained usable")
			}
		}
	}
	code, _ = h.caller.call(h.token, "POST", "/v1/realtime/tickets", map[string]any{"runtime_id": fileRuntimeID, "scope": map[string]any{"actions": []string{"session.read", "file.download"}, "workspaces": []string{}, "sessions": []string{h.session}}})
	if code != 403 {
		t.Fatalf("fresh image ticket survived grant revoke=%d", code)
	}
	if imageAuthorityRows(t, h) != before {
		t.Fatal("revoked preview/source minted authority")
	}
	t.Logf("native_image_acceptance typed_reference=true exact_source=true scanner_clean=true protected_digest=%s mime=image/png raster=1x1 readonly_denied=true foreign_device_source_denied=true stale_sync_wrong_session_denied=true same_image_pending_headers_grant_revoke=true fresh_ticket_denied=true refused_authority_rows_unchanged=true offline_model=true", expectedSHA)
}
