package relay

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"dsh-mobile-ustc/services/remote/internal/files"
	"dsh-mobile-ustc/services/remote/internal/store"
)

type exportAuthorizer interface {
	AuthorizeRealtimeExport(context.Context, store.TicketRedemption, string) (files.ExportAccess, error)
	LookupRealtimeExport(context.Context, store.TicketRedemption, files.ExportSelector) (files.Status, bool, error)
}
type exportRequest struct {
	Directory *string `json:"directory_id,omitempty"`
	Cursor    *string `json:"cursor,omitempty"`
	Source    string  `json:"source_id,omitempty"`
}
type exportNode struct {
	ID          string    `json:"source_id"`
	Kind        string    `json:"kind"`
	Origin      string    `json:"origin"`
	Name        string    `json:"name"`
	Size        *int64    `json:"size_bytes,omitempty"`
	Expires     time.Time `json:"expires_at"`
	Unavailable string    `json:"unavailable,omitempty"`
}
type exportPage struct {
	Items     []exportNode `json:"items"`
	Directory *string      `json:"directory_id"`
	Cursor    *string      `json:"cursor"`
}
type exportManifest struct {
	Source  string    `json:"source_id"`
	Origin  string    `json:"origin"`
	Name    string    `json:"name"`
	Size    *int64    `json:"size_bytes"`
	SHA     string    `json:"sha256"`
	Expires time.Time `json:"source_expires_at"`
}
type exportRouter struct {
	server     *Server
	controller *files.Exports
	database   exportAuthorizer
	mu         sync.Mutex
	jobs       map[string]*exportJob
	workers    sync.WaitGroup
}
type exportJob struct {
	router   *exportRouter
	id       string
	request  string
	session  string
	kind     string
	selector exportRequest
	phone    *liveConnection
	host     *liveConnection
	binding  files.HostBinding
	access   files.ExportAccess
	ctx      context.Context
	cancel   context.CancelFunc
	expires  time.Time
	queue    chan wireEnvelope
	mu       sync.Mutex
	until    time.Time
	timer    *time.Timer
	closed   bool
	phase    string
	file     string
}

func (server *Server) EnableExports(controller *files.Exports) {
	database, ok := server.database.(exportAuthorizer)
	if controller == nil || !ok {
		return
	}
	server.exports = &exportRouter{server: server, controller: controller, database: database, jobs: make(map[string]*exportJob)}
}
func (router *exportRouter) currentHost(host *liveConnection) bool {
	router.server.mu.Lock()
	defer router.server.mu.Unlock()
	return router.server.hosts[host.runtimeID] == host && !host.closing && host.supports(files.ExportCapability) && host.supports("session.catalog.v1") && host.peer.installation.ExpiresAt.After(time.Now())
}
func exportEnvelope(frame wireEnvelope) bool {
	return uuidPattern.MatchString(frame.RequestID) && uuidPattern.MatchString(frame.SessionID) && uuidPattern.MatchString(frame.RuntimeEpoch) && frame.UserID == "" && frame.DeviceID == "" && frame.PayloadSHA256 == "" && frame.SubscriptionID == "" && frame.SyncID == ""
}
func exportCode(err error) string {
	switch {
	case errors.Is(err, files.ErrConflict), errors.Is(err, store.ErrCommandConflict):
		return "command.request_conflict"
	case errors.Is(err, files.ErrStale):
		return "file.state_changed"
	case errors.Is(err, files.ErrInvalid):
		return "protocol.invalid"
	case errors.Is(err, files.ErrQuota):
		return "file.quota_exceeded"
	case errors.Is(err, files.ErrScanUnavailable):
		return "file.scanner_unavailable"
	case errors.Is(err, files.ErrAccess), errors.Is(err, store.ErrAccessDenied), errors.Is(err, store.ErrTicketInvalid):
		return "access.denied"
	case errors.Is(err, store.ErrRuntimeConnectionStale):
		return "runtime.changed"
	default:
		return "file.unavailable"
	}
}

func exportObject(raw json.RawMessage, required []string, optional ...string) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return false
	}
	allowed := map[string]bool{}
	for _, key := range required {
		allowed[key] = true
		if _, ok := fields[key]; !ok {
			return false
		}
	}
	for _, key := range optional {
		allowed[key] = true
	}
	for key := range fields {
		if !allowed[key] {
			return false
		}
	}
	return true
}
func (node *exportNode) UnmarshalJSON(raw []byte) error {
	type plain exportNode
	var value plain
	if err := decodePayload(raw, &value); err != nil {
		return err
	}
	required := []string{"source_id", "kind", "origin", "name", "expires_at"}
	var optional []string
	if value.Kind == "file" {
		required = append(required, "size_bytes")
		optional = append(optional, "unavailable")
	}
	if !exportObject(raw, required, optional...) {
		return errors.New("invalid export node")
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	if _, present := fields["unavailable"]; present && value.Unavailable != "file.too_large" {
		return errors.New("invalid export availability")
	}
	*node = exportNode(value)
	return nil
}
func exportErrorAllowed(code string) bool {
	switch code {
	case "access.denied", "runtime.changed", "runtime.offline", "protocol.unsupported", "protocol.invalid", "rate.limited", "file.export_unavailable", "file.export_changed", "file.export_unsupported", "file.too_large", "file.unavailable", "file.scanner_unavailable", "file.quota_exceeded", "file.state_changed", "command.request_conflict":
		return true
	}
	return false
}
func (router *exportRouter) phoneError(ctx context.Context, phone *liveConnection, frame wireEnvelope, code string) {
	_ = phone.sendJSON(ctx, map[string]any{"v": 1, "type": "file.export.error", "request_id": frame.RequestID, "runtime_id": phone.runtimeID, "runtime_epoch": frame.RuntimeEpoch, "session_id": frame.SessionID, "payload": map[string]string{"code": code}})
}

func (router *exportRouter) request(parent context.Context, phone *liveConnection, frame wireEnvelope) {
	if phone.peer.role != "device" || !phone.supports(files.ExportCapability) || !exportEnvelope(frame) || frame.RuntimeID != phone.runtimeID {
		router.server.sendProtocolError(parent, phone, "protocol.invalid", &frame)
		return
	}
	if frame.Type == "file.export.cancel" {
		var empty struct{}
		if !exportObject(frame.Payload, nil) || decodePayload(frame.Payload, &empty) != nil {
			router.phoneError(parent, phone, frame, "protocol.invalid")
			return
		}
		router.mu.Lock()
		var found *exportJob
		for _, job := range router.jobs {
			if job.phone == phone && job.request == frame.RequestID && job.session == frame.SessionID && job.binding.RuntimeEpoch == frame.RuntimeEpoch {
				found = job
				break
			}
		}
		router.mu.Unlock()
		if found != nil {
			router.finish(found, "access.denied", false)
		}
		return
	}
	var selector exportRequest
	shape := exportObject(frame.Payload, nil, "directory_id", "cursor")
	if frame.Type == "file.export.request" {
		shape = exportObject(frame.Payload, []string{"source_id"})
	}
	if !shape || decodePayload(frame.Payload, &selector) != nil {
		router.phoneError(parent, phone, frame, "protocol.invalid")
		return
	}
	if frame.Type == "file.export.request" {
		if !uuidPattern.MatchString(selector.Source) || selector.Directory != nil || selector.Cursor != nil {
			router.phoneError(parent, phone, frame, "protocol.invalid")
			return
		}
	}
	if frame.Type == "file.exports.list" {
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(frame.Payload, &fields)
		if _, present := fields["directory_id"]; present && selector.Directory == nil {
			router.phoneError(parent, phone, frame, "protocol.invalid")
			return
		}
		if _, present := fields["cursor"]; present && selector.Cursor == nil {
			router.phoneError(parent, phone, frame, "protocol.invalid")
			return
		}
		if selector.Source != "" || selector.Directory != nil && !uuidPattern.MatchString(*selector.Directory) || selector.Cursor != nil && (!uuidPattern.MatchString(*selector.Cursor) || selector.Directory == nil) {
			router.phoneError(parent, phone, frame, "protocol.invalid")
			return
		}
	}
	check, cancel := context.WithTimeout(parent, 2*time.Second)
	access, err := router.database.AuthorizeRealtimeExport(check, phone.peer.redemption, frame.SessionID)
	cancel()
	if err != nil {
		router.phoneError(parent, phone, frame, exportCode(err))
		return
	}
	host := router.server.hostForRuntime(phone.runtimeID)
	if host != nil && (!host.supports(files.ExportCapability) || !host.supports("session.catalog.v1")) {
		router.phoneError(parent, phone, frame, "protocol.unsupported")
		return
	}
	if host == nil || !router.currentHost(host) {
		router.phoneError(parent, phone, frame, "runtime.offline")
		return
	}
	if host.runtimeEpoch != frame.RuntimeEpoch {
		router.phoneError(parent, phone, frame, "runtime.changed")
		return
	}
	if frame.Type == "file.export.request" {
		check, cancel := context.WithTimeout(parent, 2*time.Second)
		status, found, err := router.database.LookupRealtimeExport(check, phone.peer.redemption, files.ExportSelector{RequestID: frame.RequestID, RuntimeID: phone.runtimeID, SessionID: frame.SessionID, RuntimeEpoch: frame.RuntimeEpoch, SourceID: selector.Source})
		cancel()
		if err != nil {
			router.phoneError(parent, phone, frame, exportCode(err))
			return
		}
		if found {
			_ = router.sendExisting(parent, phone, host, frame, status)
			return
		}
	}
	id, err := randomUUID()
	if err != nil {
		router.phoneError(parent, phone, frame, "file.unavailable")
		return
	}
	expires := time.Now().Add(5 * time.Minute)
	if limit, ok := parent.Deadline(); ok && limit.Before(expires) {
		expires = limit
	}
	if host.peer.installation.ExpiresAt.Before(expires) {
		expires = host.peer.installation.ExpiresAt
	}
	ctx, stop := context.WithDeadline(parent, expires)
	job := &exportJob{router: router, id: id, request: frame.RequestID, session: frame.SessionID, kind: frame.Type, selector: selector, phone: phone, host: host, access: access, ctx: ctx, cancel: stop, expires: expires, queue: make(chan wireEnvelope, 8), phase: "preparing",
		binding: files.HostBinding{InstallationID: host.peer.installation.InstallationID, KeyVersion: host.peer.installation.KeyVersion, RuntimeID: host.runtimeID, RuntimeEpoch: host.runtimeEpoch, ConnectionID: host.connectionID, CredentialExpiresAt: host.peer.installation.ExpiresAt}}
	job.until = access.LeaseUntil
	if expires.Before(job.until) {
		job.until = expires
	}
	router.mu.Lock()
	hosts, phones := 0, 0
	for _, active := range router.jobs {
		if active.host == host {
			hosts++
		}
		if active.phone == phone {
			phones++
		}
		if active.phone.peer.deviceID == phone.peer.deviceID && active.request == frame.RequestID {
			same := active.phone == phone && active.kind == frame.Type && active.session == frame.SessionID && active.binding.RuntimeEpoch == frame.RuntimeEpoch && active.selector.Source == selector.Source && sameOptional(active.selector.Directory, selector.Directory) && sameOptional(active.selector.Cursor, selector.Cursor)
			router.mu.Unlock()
			stop()
			if !same {
				router.phoneError(parent, phone, frame, "command.request_conflict")
			}
			return
		}
	}
	if len(router.jobs) >= 256 || hosts >= 8 || phones >= 4 {
		router.mu.Unlock()
		stop()
		router.phoneError(parent, phone, frame, "rate.limited")
		return
	}
	job.timer = time.AfterFunc(max(0, time.Until(job.until)-100*time.Millisecond), job.cancel)
	router.jobs[id] = job
	router.workers.Add(2)
	router.mu.Unlock()
	go job.run()
	go func() {
		defer router.workers.Done()
		select {
		case <-ctx.Done():
		case <-phone.done:
		case <-host.done:
		}
		router.finish(job, "access.denied", true)
	}()
	payload := map[string]any{"user_id": access.UserID, "device_id": phone.peer.deviceID, "key_version": access.DeviceKeyVersion, "grant_version": access.GrantVersion, "allow_workspace": access.AllowWorkspace, "lease_until": job.until, "expires_at": expires}
	if selector.Directory != nil {
		payload["directory_id"] = *selector.Directory
	}
	if selector.Cursor != nil {
		payload["cursor"] = *selector.Cursor
	}
	if frame.Type == "file.export.request" {
		payload["source_id"] = selector.Source
		payload["origin_request_id"] = frame.RequestID
	}
	if err := job.sendHost(frame.Type, payload); err != nil {
		router.finish(job, "runtime.offline", true)
	}
}
func sameOptional(left, right *string) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}
func (router *exportRouter) sendExisting(ctx context.Context, phone, host *liveConnection, frame wireEnvelope, status files.Status) error {
	if !router.currentHost(host) {
		return files.ErrAccess
	}
	return phone.sendJSONBeforeWrite(ctx, map[string]any{"v": 1, "type": "file.export.accepted", "request_id": frame.RequestID, "runtime_id": phone.runtimeID, "runtime_epoch": frame.RuntimeEpoch, "session_id": frame.SessionID, "payload": map[string]any{"file": status}}, func() error {
		_, err := router.database.AuthorizeRealtimeExport(ctx, phone.peer.redemption, frame.SessionID)
		return err
	})
}
func (job *exportJob) sendHost(kind string, payload any) error {
	ctx, cancel := context.WithTimeout(job.ctx, 2*time.Second)
	defer cancel()
	return job.host.sendJSON(ctx, map[string]any{"v": 1, "type": kind, "request_id": job.id, "runtime_id": job.binding.RuntimeID, "runtime_epoch": job.binding.RuntimeEpoch, "session_id": job.session, "payload": payload})
}
func (job *exportJob) authorize() error {
	if job.ctx.Err() != nil || !job.router.currentHost(job.host) {
		return files.ErrAccess
	}
	select {
	case <-job.phone.done:
		return files.ErrAccess
	default:
	}
	ctx, cancel := context.WithTimeout(job.ctx, time.Second)
	defer cancel()
	access, err := job.router.database.AuthorizeRealtimeExport(ctx, job.phone.peer.redemption, job.session)
	if err != nil {
		return err
	}
	if access.UserID != job.access.UserID || access.DeviceKeyVersion != job.access.DeviceKeyVersion || access.GrantVersion != job.access.GrantVersion || access.AllowWorkspace != job.access.AllowWorkspace {
		return files.ErrAccess
	}
	return nil
}
func (job *exportJob) sendPhone(kind string, payload any) error {
	return job.phone.sendJSONBeforeWrite(job.ctx, map[string]any{"v": 1, "type": kind, "request_id": job.request, "runtime_id": job.binding.RuntimeID, "runtime_epoch": job.binding.RuntimeEpoch, "session_id": job.session, "payload": payload}, job.authorize)
}
func (router *exportRouter) finish(job *exportJob, code string, notify bool) {
	router.mu.Lock()
	if router.jobs[job.id] != job {
		router.mu.Unlock()
		return
	}
	delete(router.jobs, job.id)
	router.mu.Unlock()
	job.mu.Lock()
	job.closed = true
	job.timer.Stop()
	job.cancel()
	job.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if router.currentHost(job.host) {
		_ = job.host.sendJSON(ctx, map[string]any{"v": 1, "type": "file.export.abort", "request_id": job.id, "runtime_id": job.binding.RuntimeID, "runtime_epoch": job.binding.RuntimeEpoch, "session_id": job.session, "payload": map[string]string{"code": code}})
	}
	if notify {
		select {
		case <-job.phone.done:
			return
		default:
		}
		router.phoneError(ctx, job.phone, wireEnvelope{RequestID: job.request, RuntimeEpoch: job.binding.RuntimeEpoch, SessionID: job.session}, code)
	}
}
func (router *exportRouter) closeConnection(live *liveConnection) {
	router.mu.Lock()
	jobs := []*exportJob{}
	for _, job := range router.jobs {
		if job.phone == live || job.host == live {
			jobs = append(jobs, job)
		}
	}
	router.mu.Unlock()
	for _, job := range jobs {
		router.finish(job, "runtime.offline", job.phone != live)
	}
}

func (router *exportRouter) hostFrame(parent context.Context, host *liveConnection, frame wireEnvelope) {
	if !host.supports(files.ExportCapability) || !router.currentHost(host) {
		router.server.sendProtocolError(parent, host, "access.denied", &frame)
		return
	}
	if frame.Type == "file.export.renew" {
		router.renew(parent, host, frame)
		return
	}
	if !exportEnvelope(frame) || frame.RuntimeID != host.runtimeID || frame.RuntimeEpoch != host.runtimeEpoch {
		router.server.sendProtocolError(parent, host, "protocol.invalid", &frame)
		return
	}
	router.mu.Lock()
	job := router.jobs[frame.RequestID]
	router.mu.Unlock()
	if job == nil {
		return
	}
	if job.host != host || frame.SessionID != job.session {
		router.server.sendProtocolError(parent, host, "access.denied", &frame)
		return
	}
	select {
	case <-job.ctx.Done():
	case job.queue <- frame:
	default:
		router.finish(job, "rate.limited", true)
	}
}
func (router *exportRouter) renew(parent context.Context, host *liveConnection, frame wireEnvelope) {
	var payload struct {
		IDs []string `json:"operation_ids"`
	}
	if frame.RuntimeID != host.runtimeID || frame.RuntimeEpoch != host.runtimeEpoch || !uuidPattern.MatchString(frame.RequestID) || frame.SessionID != "" || frame.DeviceID != "" || frame.UserID != "" || frame.PayloadSHA256 != "" || frame.SubscriptionID != "" || frame.SyncID != "" || decodePayload(frame.Payload, &payload) != nil || len(payload.IDs) < 1 || len(payload.IDs) > 8 {
		router.server.sendProtocolError(parent, host, "protocol.invalid", &frame)
		return
	}
	leases := []map[string]any{}
	seen := map[string]bool{}
	for _, id := range payload.IDs {
		if !uuidPattern.MatchString(id) || seen[id] {
			router.server.sendProtocolError(parent, host, "protocol.invalid", &frame)
			return
		}
		seen[id] = true
		router.mu.Lock()
		job := router.jobs[id]
		router.mu.Unlock()
		if job == nil || job.host != host {
			continue
		}
		ctx, cancel := context.WithTimeout(job.ctx, time.Second)
		access, err := router.database.AuthorizeRealtimeExport(ctx, job.phone.peer.redemption, job.session)
		cancel()
		if err != nil || access.UserID != job.access.UserID || access.DeviceKeyVersion != job.access.DeviceKeyVersion || access.GrantVersion != job.access.GrantVersion || access.AllowWorkspace != job.access.AllowWorkspace || !router.currentHost(host) {
			router.finish(job, "access.denied", true)
			continue
		}
		job.mu.Lock()
		until := access.LeaseUntil
		if job.expires.Before(until) {
			until = job.expires
		}
		valid := !job.closed && job.ctx.Err() == nil && time.Now().Before(job.until.Add(-100*time.Millisecond)) && job.timer.Stop()
		if valid {
			job.until = until
			job.timer.Reset(max(0, time.Until(until)-100*time.Millisecond))
			leases = append(leases, map[string]any{"operation_id": id, "lease_until": until, "expires_at": job.expires})
		}
		job.mu.Unlock()
		if !valid {
			router.finish(job, "access.denied", true)
		}
	}
	_ = host.sendJSON(parent, map[string]any{"v": 1, "type": "file.export.renewed", "request_id": frame.RequestID, "runtime_id": host.runtimeID, "runtime_epoch": host.runtimeEpoch, "payload": map[string]any{"leases": leases}})
}

func validExportPage(page exportPage, job *exportJob) bool {
	if page.Items == nil || len(page.Items) > 16 || !sameOptional(page.Directory, job.selector.Directory) || page.Cursor != nil && !uuidPattern.MatchString(*page.Cursor) {
		return false
	}
	seen := map[string]bool{}
	for _, item := range page.Items {
		if !uuidPattern.MatchString(item.ID) || seen[item.ID] || !item.Expires.After(time.Now()) || item.Expires.After(job.expires) || item.Origin != "session_attachment" && item.Origin != "workspace_artifact" || item.Origin == "workspace_artifact" && !job.access.AllowWorkspace {
			return false
		}
		seen[item.ID] = true
		if _, err := files.NormalizeRegistration(files.UploadRegistration{RequestID: job.id, RuntimeID: job.binding.RuntimeID, SessionID: job.session, Name: item.Name, SizeBytes: 0, SHA256: "0000000000000000000000000000000000000000000000000000000000000000"}); err != nil {
			return false
		}
		if item.Kind == "directory" {
			if item.Size != nil || item.Unavailable != "" {
				return false
			}
		} else if item.Kind == "file" {
			if item.Size == nil || *item.Size < 0 || *item.Size > 9007199254740991 || item.Unavailable != "" && item.Unavailable != "file.too_large" || *item.Size > files.MaxExportBytes && item.Unavailable != "file.too_large" {
				return false
			}
		} else {
			return false
		}
	}
	return true
}
func (job *exportJob) run() {
	defer job.router.workers.Done()
	for {
		select {
		case <-job.ctx.Done():
			return
		case frame := <-job.queue:
			if err := job.authorize(); err != nil {
				job.router.finish(job, "access.denied", true)
				return
			}
			switch frame.Type {
			case "file.export.error":
				var value struct {
					Code string `json:"code"`
				}
				if !exportObject(frame.Payload, []string{"code"}) || decodePayload(frame.Payload, &value) != nil || !exportErrorAllowed(value.Code) {
					value.Code = "protocol.invalid"
				}
				job.router.finish(job, value.Code, true)
				return
			case "file.exports.result":
				var page exportPage
				if job.kind != "file.exports.list" || !exportObject(frame.Payload, []string{"items", "directory_id", "cursor"}) || decodePayload(frame.Payload, &page) != nil || !validExportPage(page, job) {
					job.router.finish(job, "protocol.invalid", true)
					return
				}
				if err := job.sendPhone("file.exports.result", page); err != nil {
					job.router.finish(job, "access.denied", false)
					return
				}
				job.router.finish(job, "access.denied", false)
				return
			case "file.export.manifest":
				var manifest exportManifest
				if job.kind != "file.export.request" || job.phase != "preparing" || !exportObject(frame.Payload, []string{"source_id", "origin", "name", "size_bytes", "sha256", "source_expires_at"}) || decodePayload(frame.Payload, &manifest) != nil || manifest.Size == nil || manifest.Source != job.selector.Source || manifest.Origin == "workspace_artifact" && !job.access.AllowWorkspace {
					job.router.finish(job, "protocol.invalid", true)
					return
				}
				input := files.ExportRegistration{Origin: manifest.Origin, RequestID: job.request, RuntimeID: job.binding.RuntimeID, SessionID: job.session, SourceID: manifest.Source, Name: manifest.Name, SizeBytes: *manifest.Size, SHA256: manifest.SHA, SourceExpiresAt: manifest.Expires}
				var prepared files.UploadPrepared
				var err error
				for {
					if err = job.authorize(); err != nil {
						break
					}
					ctx, cancel := context.WithTimeout(job.ctx, 2*time.Second)
					prepared, err = job.router.controller.Register(ctx, job.access.Actor, job.binding, input)
					cancel()
					if !retryExport(err) || !waitExport(job.ctx) {
						break
					}
				}
				if err != nil {
					job.router.finish(job, exportCode(err), true)
					return
				}
				job.file = prepared.File.ID
				if prepared.Upload == nil {
					if err := job.sendPhone("file.export.accepted", map[string]any{"file": prepared.File}); err != nil {
						job.router.finish(job, "access.denied", false)
						return
					}
					job.router.finish(job, "access.denied", false)
					return
				}
				job.phase = "uploading"
				if err := job.sendHost("file.export.upload", prepared); err != nil {
					job.router.finish(job, "runtime.offline", true)
					return
				}
			case "file.export.uploaded":
				var payload struct {
					File string `json:"file_id"`
				}
				if job.phase != "uploading" || !exportObject(frame.Payload, []string{"file_id"}) || decodePayload(frame.Payload, &payload) != nil || payload.File != job.file {
					job.router.finish(job, "protocol.invalid", true)
					return
				}
				var status files.Status
				var err error
				for {
					if err = job.authorize(); err != nil {
						break
					}
					ctx, cancel := context.WithTimeout(job.ctx, 2*time.Second)
					status, err = job.router.controller.Commit(ctx, job.access.Actor, job.binding, job.file)
					cancel()
					if !retryExport(err) || !waitExport(job.ctx) {
						break
					}
				}
				if err != nil {
					job.router.finish(job, exportCode(err), true)
					return
				}
				if err := job.sendHost("file.export.committed", map[string]string{"file_id": job.file}); err != nil {
					job.router.finish(job, "runtime.offline", true)
					return
				}
				_ = job.sendPhone("file.export.accepted", map[string]any{"file": status})
				job.router.finish(job, "access.denied", false)
				return
			default:
				job.router.finish(job, "protocol.invalid", true)
				return
			}
		}
	}
}
func retryExport(err error) bool {
	return errors.Is(err, files.ErrUnavailable) || errors.Is(err, files.ErrBlobUnavailable) || errors.Is(err, files.ErrScanUnavailable)
}
func waitExport(ctx context.Context) bool {
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
