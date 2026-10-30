package httpapi

import (
	"net/http"

	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/store"
)

func (api *API) listRuntimeGrants(response http.ResponseWriter, request *http.Request) {
	limit, cursor, ok := directoryPageQuery(request)
	runtimeID := request.PathValue("id")
	if !ok || !uuidPattern.MatchString(runtimeID) {
		writeError(response, http.StatusBadRequest, "protocol.invalid")
		return
	}
	principal, _ := auth.PrincipalFromContext(request.Context())
	deviceID, _ := request.Context().Value(deviceContextKey{}).(string)
	page, err := api.database.ListRuntimeGrants(request.Context(), store.UserIdentity{Issuer: principal.Issuer, Subject: principal.Subject}, deviceID, principal.ProofKeyJKT, runtimeID, limit, cursor)
	if err != nil {
		api.writeStoreError(response, err)
		return
	}
	writeData(response, http.StatusOK, page)
}
