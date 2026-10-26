package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/push"
)

func pushOperation(request *http.Request) (context.Context, context.CancelFunc, push.Actor) {
	principal, _ := auth.PrincipalFromContext(request.Context())
	device, _ := request.Context().Value(deviceContextKey{}).(string)
	ctx, cancel := context.WithTimeout(request.Context(), 3*time.Second)
	return ctx, cancel, push.Actor{Issuer: principal.Issuer, Subject: principal.Subject, DeviceID: device, ProofKeyJKT: principal.ProofKeyJKT}
}
func pushError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, push.ErrInvalid):
		writeError(response, http.StatusBadRequest, "push.invalid")
	case errors.Is(err, push.ErrAccess):
		writeError(response, http.StatusForbidden, "access.denied")
	case errors.Is(err, push.ErrConflict):
		writeError(response, http.StatusConflict, "push.conflict")
	case errors.Is(err, push.ErrExpired):
		writeError(response, http.StatusGone, "push.expired")
	default:
		writeError(response, http.StatusServiceUnavailable, "push.unavailable")
	}
}
func (api *API) pushCapabilities(w http.ResponseWriter, r *http.Request) {
	writeData(w, 200, api.push.Capabilities())
}
func (api *API) pushRegister(w http.ResponseWriter, r *http.Request) {
	var body push.Registration
	if !decodeBody(w, r, &body) {
		return
	}
	ctx, cancel, actor := pushOperation(r)
	defer cancel()
	binding, err := api.push.Register(ctx, actor, body)
	if err != nil {
		pushError(w, err)
		return
	}
	writeData(w, 201, map[string]any{"binding": binding})
}
func (api *API) pushStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel, actor := pushOperation(r)
	defer cancel()
	binding, err := api.push.Status(ctx, actor, r.PathValue("id"))
	if err != nil {
		pushError(w, err)
		return
	}
	writeData(w, 200, map[string]any{"binding": binding})
}
func (api *API) pushConfirm(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Challenge string `json:"challenge"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	ctx, cancel, actor := pushOperation(r)
	defer cancel()
	binding, err := api.push.Confirm(ctx, actor, r.PathValue("id"), body.Challenge)
	if err != nil {
		pushError(w, err)
		return
	}
	writeData(w, 200, map[string]any{"binding": binding})
}
func (api *API) pushRenew(w http.ResponseWriter, r *http.Request) {
	var body struct{}
	if !decodeBody(w, r, &body) {
		return
	}
	ctx, cancel, actor := pushOperation(r)
	defer cancel()
	binding, err := api.push.Renew(ctx, actor, r.PathValue("id"))
	if err != nil {
		pushError(w, err)
		return
	}
	writeData(w, 200, map[string]any{"binding": binding})
}
func (api *API) pushRevoke(w http.ResponseWriter, r *http.Request) {
	// Deletion only, with no OAuth token/cookie and no secret in a URL or response.
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength > 0 || len(r.TransferEncoding) > 0 {
		writeError(w, 400, "push.invalid")
		return
	}
	credential := ""
	if len(r.Header.Values("Authorization")) == 1 && strings.HasPrefix(r.Header.Get("Authorization"), "DSH-Push-Revoke ") {
		credential = strings.TrimPrefix(r.Header.Get("Authorization"), "DSH-Push-Revoke ")
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if err := api.push.Revoke(ctx, r.PathValue("id"), credential); err != nil {
		pushError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (api *API) pushInbox(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	for key := range query {
		if key != "binding_id" && key != "after" {
			writeError(w, 400, "push.invalid")
			return
		}
	}
	if len(query["binding_id"]) != 1 || len(query["after"]) > 1 {
		writeError(w, 400, "push.invalid")
		return
	}
	ctx, cancel, actor := pushOperation(r)
	defer cancel()
	page, err := api.push.Inbox(ctx, actor, query.Get("binding_id"), query.Get("after"))
	if err != nil {
		pushError(w, err)
		return
	}
	writeData(w, 200, page)
}
func (api *API) pushReference(w http.ResponseWriter, r *http.Request) {
	ctx, cancel, actor := pushOperation(r)
	defer cancel()
	ref, err := api.push.Reference(ctx, actor, r.PathValue("id"))
	if err != nil {
		pushError(w, err)
		return
	}
	writeData(w, 200, map[string]any{"reference": ref})
}
func (api *API) pushReceipt(w http.ResponseWriter, r *http.Request) {
	var body struct {
		State string `json:"state"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	ctx, cancel, actor := pushOperation(r)
	defer cancel()
	if err := api.push.Receipt(ctx, actor, r.PathValue("id"), body.State); err != nil {
		pushError(w, err)
		return
	}
	writeData(w, 200, map[string]bool{"recorded": true})
}
