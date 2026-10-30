package httpapi

import (
	"net/http"

	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/store"
)

func (api *API) sessionDirectory(w http.ResponseWriter, r *http.Request) {
	limit, cursor, ok := directoryPageQuery(r)
	id := r.PathValue("id")
	if !ok || !uuidPattern.MatchString(id) {
		writeError(w, http.StatusBadRequest, "protocol.invalid")
		return
	}
	principal, _ := auth.PrincipalFromContext(r.Context())
	device, _ := r.Context().Value(deviceContextKey{}).(string)
	page, err := api.database.SessionDirectory(r.Context(), store.UserIdentity{Issuer: principal.Issuer, Subject: principal.Subject}, device, principal.ProofKeyJKT, id, limit, cursor)
	if err != nil {
		api.writeStoreError(w, err)
		return
	}
	writeData(w, http.StatusOK, page)
}
