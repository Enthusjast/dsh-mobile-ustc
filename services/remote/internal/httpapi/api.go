package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/store"
)

const maxJSONRequestBytes = 16 << 10

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type Repository interface {
	Ready(context.Context) error
	ActiveDevice(context.Context, store.UserIdentity, string) (string, error)
	RegisterDevice(context.Context, store.DeviceRegistration) (string, error)
	RevokeDevice(context.Context, string, string, string) error
	ListHosts(context.Context, store.UserIdentity) ([]store.Host, error)
	ListRuntimes(context.Context, store.UserIdentity) ([]store.Runtime, error)
	ListSessions(context.Context, store.UserIdentity, string) ([]store.Session, error)
	CommandStatus(context.Context, store.UserIdentity, string, string) (store.CommandStatus, error)
}

type API struct {
	database Repository
	identity *auth.Authenticator
}

type deviceContextKey struct{}

type deviceRequest struct {
	Name              string          `json:"name"`
	ApprovalPublicJWK json.RawMessage `json:"approval_public_jwk"`
	ApprovalProof     string          `json:"approval_proof"`
	ProofPublicJWK    json.RawMessage `json:"proof_public_jwk"`
}

func New(database Repository, identity *auth.Authenticator) http.Handler {
	api := &API{database: database, identity: identity}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", api.health)
	mux.HandleFunc("GET /readyz", api.ready)
	mux.Handle("GET /v1/me", api.authenticated(http.HandlerFunc(api.me)))
	mux.Handle("POST /v1/devices", api.authenticated(http.HandlerFunc(api.registerDevice)))
	mux.Handle("DELETE /v1/devices/{id}", api.protected(http.HandlerFunc(api.revokeDevice)))
	mux.Handle("GET /v1/hosts", api.protected(http.HandlerFunc(api.listHosts)))
	mux.Handle("GET /v1/runtimes", api.protected(http.HandlerFunc(api.listRuntimes)))
	mux.Handle("GET /v1/runtimes/{id}/sessions", api.protected(http.HandlerFunc(api.listSessions)))
	mux.Handle("GET /v1/commands/{id}", api.protected(http.HandlerFunc(api.commandStatus)))
	return mux
}

func (api *API) protected(next http.Handler) http.Handler {
	return api.authenticated(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		principal, _ := auth.PrincipalFromContext(request.Context())
		deviceID, err := api.database.ActiveDevice(request.Context(), store.UserIdentity{Issuer: principal.Issuer, Subject: principal.Subject}, principal.ProofKeyJKT)
		if err != nil {
			api.writeStoreError(response, err)
			return
		}
		ctx := context.WithValue(request.Context(), deviceContextKey{}, deviceID)
		next.ServeHTTP(response, request.WithContext(ctx))
	}))
}

func (api *API) authenticated(next http.Handler) http.Handler {
	return api.identity.Middleware(next)
}

func (api *API) health(response http.ResponseWriter, _ *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusNoContent)
}

func (api *API) ready(response http.ResponseWriter, request *http.Request) {
	ctx, cancel := context.WithTimeout(request.Context(), time.Second)
	defer cancel()
	if err := api.database.Ready(ctx); err != nil {
		writeError(response, http.StatusServiceUnavailable, "internal")
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusNoContent)
}

func (api *API) me(response http.ResponseWriter, request *http.Request) {
	principal, _ := auth.PrincipalFromContext(request.Context())
	writeData(response, http.StatusOK, map[string]any{
		"issuer": principal.Issuer, "subject": principal.Subject, "client_id": principal.ClientID,
		"scopes": sortedScopes(principal.Scopes),
	})
}

func (api *API) registerDevice(response http.ResponseWriter, request *http.Request) {
	var input deviceRequest
	if !decodeBody(response, request, &input) {
		writeError(response, http.StatusBadRequest, "protocol.invalid")
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" || utf8.RuneCountInString(input.Name) > 160 || strings.IndexFunc(input.Name, unicode.IsControl) >= 0 {
		writeError(response, http.StatusBadRequest, "protocol.invalid")
		return
	}
	approvalThumbprint, err := auth.PublicP256JWKThumbprintJSON(input.ApprovalPublicJWK)
	if err != nil {
		writeError(response, http.StatusBadRequest, "device.key_invalid")
		return
	}
	proofThumbprint, err := auth.PublicP256JWKThumbprintJSON(input.ProofPublicJWK)
	if err != nil {
		writeError(response, http.StatusBadRequest, "device.key_invalid")
		return
	}
	principal, _ := auth.PrincipalFromContext(request.Context())
	if proofThumbprint != principal.ProofKeyJKT {
		writeError(response, http.StatusForbidden, "access.denied")
		return
	}
	if proofThumbprint == approvalThumbprint {
		writeError(response, http.StatusBadRequest, "device.key_invalid")
		return
	}
	if err := api.identity.VerifyDeviceRegistrationProof(input.ApprovalProof, input.ApprovalPublicJWK, principal, input.Name, proofThumbprint); err != nil {
		writeError(response, http.StatusBadRequest, "device.proof_invalid")
		return
	}
	id, err := api.database.RegisterDevice(request.Context(), store.DeviceRegistration{
		Issuer: principal.Issuer, Subject: principal.Subject, Name: input.Name,
		ApprovalPublicJWK: input.ApprovalPublicJWK, ApprovalKeyThumbprint: approvalThumbprint,
		ProofPublicJWK: input.ProofPublicJWK, ProofKeyThumbprint: proofThumbprint,
	})
	if err != nil {
		api.writeStoreError(response, err)
		return
	}
	writeData(response, http.StatusCreated, map[string]any{"device_id": id, "key_version": 1})
}

func (api *API) revokeDevice(response http.ResponseWriter, request *http.Request) {
	id := request.PathValue("id")
	if !uuidPattern.MatchString(id) {
		writeError(response, http.StatusBadRequest, "protocol.invalid")
		return
	}
	principal, _ := auth.PrincipalFromContext(request.Context())
	if err := api.database.RevokeDevice(request.Context(), principal.Issuer, principal.Subject, id); err != nil {
		api.writeStoreError(response, err)
		return
	}
	writeData(response, http.StatusOK, map[string]any{"revoked": true})
}

func (api *API) listHosts(response http.ResponseWriter, request *http.Request) {
	principal, _ := auth.PrincipalFromContext(request.Context())
	items, err := api.database.ListHosts(request.Context(), store.UserIdentity{Issuer: principal.Issuer, Subject: principal.Subject})
	if err != nil {
		api.writeStoreError(response, err)
		return
	}
	writeData(response, http.StatusOK, map[string]any{"items": items})
}

func (api *API) listRuntimes(response http.ResponseWriter, request *http.Request) {
	principal, _ := auth.PrincipalFromContext(request.Context())
	items, err := api.database.ListRuntimes(request.Context(), store.UserIdentity{Issuer: principal.Issuer, Subject: principal.Subject})
	if err != nil {
		api.writeStoreError(response, err)
		return
	}
	writeData(response, http.StatusOK, map[string]any{"items": items})
}

func (api *API) listSessions(response http.ResponseWriter, request *http.Request) {
	runtimeID := request.PathValue("id")
	if !uuidPattern.MatchString(runtimeID) {
		writeError(response, http.StatusBadRequest, "protocol.invalid")
		return
	}
	principal, _ := auth.PrincipalFromContext(request.Context())
	items, err := api.database.ListSessions(request.Context(), store.UserIdentity{Issuer: principal.Issuer, Subject: principal.Subject}, runtimeID)
	if err != nil {
		api.writeStoreError(response, err)
		return
	}
	writeData(response, http.StatusOK, map[string]any{"items": items})
}

func (api *API) commandStatus(response http.ResponseWriter, request *http.Request) {
	requestID := request.PathValue("id")
	deviceID := request.URL.Query().Get("device_id")
	if !uuidPattern.MatchString(requestID) || !uuidPattern.MatchString(deviceID) {
		writeError(response, http.StatusBadRequest, "protocol.invalid")
		return
	}
	principal, _ := auth.PrincipalFromContext(request.Context())
	activeDeviceID, _ := request.Context().Value(deviceContextKey{}).(string)
	if deviceID != activeDeviceID {
		writeError(response, http.StatusForbidden, "access.denied")
		return
	}
	status, err := api.database.CommandStatus(request.Context(), store.UserIdentity{Issuer: principal.Issuer, Subject: principal.Subject}, deviceID, requestID)
	if err != nil {
		api.writeStoreError(response, err)
		return
	}
	writeData(response, http.StatusOK, status)
}

func decodeBody(response http.ResponseWriter, request *http.Request, target any) bool {
	if !strings.EqualFold(strings.TrimSpace(strings.Split(request.Header.Get("Content-Type"), ";")[0]), "application/json") {
		return false
	}
	body, err := io.ReadAll(http.MaxBytesReader(response, request.Body, maxJSONRequestBytes))
	if err != nil || auth.ValidateJSONObject(body) != nil {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return false
	}
	var trailing any
	return errors.Is(decoder.Decode(&trailing), io.EOF)
}

func (api *API) writeStoreError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrIdentityNotProvisioned), errors.Is(err, store.ErrDeviceNotFound):
		writeError(response, http.StatusForbidden, "access.denied")
	case errors.Is(err, store.ErrDatabaseUnavailable):
		writeError(response, http.StatusServiceUnavailable, "internal")
	default:
		writeError(response, http.StatusInternalServerError, "internal")
	}
}

func writeData(response http.ResponseWriter, status int, data any) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(map[string]any{"ok": true, "data": data})
}

func writeError(response http.ResponseWriter, status int, code string) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(map[string]any{"ok": false, "error": map[string]string{"code": code}})
}

func sortedScopes(scopes map[string]struct{}) []string {
	items := make([]string, 0, len(scopes))
	for scope := range scopes {
		items = append(items, scope)
	}
	sort.Strings(items)
	return items
}
