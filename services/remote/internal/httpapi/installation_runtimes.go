package httpapi

import (
	"net/http"

	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/store"
)

func (api *API) listInstallationRuntimes(w http.ResponseWriter, r *http.Request) {
	limit, cursor, ok := directoryPageQuery(r)
	id := r.PathValue("id")
	if !ok || !uuidPattern.MatchString(id) {
		writeError(w, http.StatusBadRequest, "protocol.invalid")
		return
	}
	principal, _ := auth.PrincipalFromContext(r.Context())
	device, _ := r.Context().Value(deviceContextKey{}).(string)
	page, err := api.database.ListInstallationRuntimes(r.Context(), store.UserIdentity{Issuer: principal.Issuer, Subject: principal.Subject}, device, principal.ProofKeyJKT, id, limit, cursor)
	if err != nil {
		api.writeStoreError(w, err)
		return
	}
	writeData(w, http.StatusOK, page)
}

func (api *API) revokeInstallationRuntime(w http.ResponseWriter, r *http.Request) {
	id, runtime := r.PathValue("id"), r.PathValue("runtime_id")
	if !uuidPattern.MatchString(id) || !uuidPattern.MatchString(runtime) || r.URL.RawQuery != "" || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		writeError(w, http.StatusBadRequest, "protocol.invalid")
		return
	}
	principal, _ := auth.PrincipalFromContext(r.Context())
	device, _ := r.Context().Value(deviceContextKey{}).(string)
	if err := api.database.RevokeInstallationRuntime(r.Context(), store.UserIdentity{Issuer: principal.Issuer, Subject: principal.Subject}, device, principal.ProofKeyJKT, id, runtime); err != nil {
		api.writeStoreError(w, err)
		return
	}
	writeData(w, http.StatusOK, map[string]bool{"revoked": true})
}
