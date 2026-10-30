package httpapi

import (
	"net/http"

	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/store"
)

func (api *API) hostDirectory(w http.ResponseWriter, r *http.Request) {
	limit, cursor, ok := directoryPageQuery(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "protocol.invalid")
		return
	}
	principal, _ := auth.PrincipalFromContext(r.Context())
	device, _ := r.Context().Value(deviceContextKey{}).(string)
	page, err := api.database.HostDirectory(r.Context(), store.UserIdentity{Issuer: principal.Issuer, Subject: principal.Subject}, device, principal.ProofKeyJKT, limit, cursor)
	if err != nil {
		api.writeStoreError(w, err)
		return
	}
	writeData(w, http.StatusOK, page)
}

func (api *API) runtimeDirectory(w http.ResponseWriter, r *http.Request) {
	limit, cursor, ok := directoryPageQuery(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "protocol.invalid")
		return
	}
	principal, _ := auth.PrincipalFromContext(r.Context())
	device, _ := r.Context().Value(deviceContextKey{}).(string)
	page, err := api.database.RuntimeDirectory(r.Context(), store.UserIdentity{Issuer: principal.Issuer, Subject: principal.Subject}, device, principal.ProofKeyJKT, limit, cursor)
	if err != nil {
		api.writeStoreError(w, err)
		return
	}
	writeData(w, http.StatusOK, page)
}
