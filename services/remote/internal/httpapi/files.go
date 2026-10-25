package httpapi

import (
	"context"
	"net/http"
	"time"

	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/files"
)

type fileRegistrationRequest struct {
	RequestID string `json:"request_id"`
	Name      string `json:"name"`
	SizeBytes *int64 `json:"size_bytes"`
	SHA256    string `json:"sha256"`
}

func fileOperation(response http.ResponseWriter, request *http.Request) (context.Context, context.CancelFunc, files.Actor, bool) {
	principal, ok := auth.PrincipalFromContext(request.Context())
	device, _ := request.Context().Value(deviceContextKey{}).(string)
	if !ok || device == "" || !principal.ExpiresAt.After(time.Now()) {
		writeError(response, http.StatusUnauthorized, "auth.expired")
		return nil, func() {}, files.Actor{}, false
	}
	until := time.Now().Add(3 * time.Second)
	if principal.ExpiresAt.Before(until) {
		until = principal.ExpiresAt
	}
	ctx, cancel := context.WithDeadline(request.Context(), until)
	return ctx, cancel, files.Actor{Issuer: principal.Issuer, Subject: principal.Subject, DeviceID: device, ProofKeyJKT: principal.ProofKeyJKT}, true
}

func (api *API) registerFile(response http.ResponseWriter, request *http.Request) {
	var input fileRegistrationRequest
	runtime, session := request.PathValue("id"), request.PathValue("session_id")
	if !uuidPattern.MatchString(runtime) || !uuidPattern.MatchString(session) || !decodeBody(response, request, &input) || input.SizeBytes == nil {
		writeError(response, http.StatusBadRequest, "protocol.invalid")
		return
	}
	ctx, cancel, actor, ok := fileOperation(response, request)
	if !ok {
		return
	}
	defer cancel()
	prepared, err := api.files.Register(ctx, actor, files.UploadRegistration{RequestID: input.RequestID, RuntimeID: runtime, SessionID: session, Name: input.Name, SizeBytes: *input.SizeBytes, SHA256: input.SHA256})
	if err != nil {
		api.writeStoreError(response, err)
		return
	}
	writeData(response, http.StatusCreated, prepared)
}

func (api *API) fileStatus(response http.ResponseWriter, request *http.Request) {
	id := request.PathValue("id")
	if !uuidPattern.MatchString(id) {
		writeError(response, http.StatusBadRequest, "protocol.invalid")
		return
	}
	ctx, cancel, actor, ok := fileOperation(response, request)
	if !ok {
		return
	}
	defer cancel()
	status, err := api.files.Status(ctx, actor, id)
	if err != nil {
		api.writeStoreError(response, err)
		return
	}
	writeData(response, http.StatusOK, map[string]any{"file": status})
}

func (api *API) fileUploadURL(response http.ResponseWriter, request *http.Request) {
	id := request.PathValue("id")
	if !uuidPattern.MatchString(id) || !decodeBody(response, request, &struct{}{}) {
		writeError(response, http.StatusBadRequest, "protocol.invalid")
		return
	}
	ctx, cancel, actor, ok := fileOperation(response, request)
	if !ok {
		return
	}
	defer cancel()
	prepared, err := api.files.Upload(ctx, actor, id)
	if err != nil {
		api.writeStoreError(response, err)
		return
	}
	writeData(response, http.StatusOK, prepared)
}

func (api *API) commitFile(response http.ResponseWriter, request *http.Request) {
	id := request.PathValue("id")
	if !uuidPattern.MatchString(id) || !decodeBody(response, request, &struct{}{}) {
		writeError(response, http.StatusBadRequest, "protocol.invalid")
		return
	}
	ctx, cancel, actor, ok := fileOperation(response, request)
	if !ok {
		return
	}
	defer cancel()
	status, err := api.files.Commit(ctx, actor, id)
	if err != nil {
		api.writeStoreError(response, err)
		return
	}
	code := http.StatusOK
	if status.State == "scanning" {
		code = http.StatusAccepted
	}
	writeData(response, code, map[string]any{"file": status})
}
