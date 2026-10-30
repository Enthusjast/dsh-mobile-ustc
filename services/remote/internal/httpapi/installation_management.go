package httpapi

import (
	"net/http"

	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/store"
)

func (api *API) listInstallations(response http.ResponseWriter, request *http.Request) {
	limit, cursor, ok := directoryPageQuery(request)
	if !ok {
		writeError(response, http.StatusBadRequest, "protocol.invalid")
		return
	}
	principal, _ := auth.PrincipalFromContext(request.Context())
	deviceID, _ := request.Context().Value(deviceContextKey{}).(string)
	page, err := api.database.ListInstallations(request.Context(), store.UserIdentity{Issuer: principal.Issuer, Subject: principal.Subject}, deviceID, principal.ProofKeyJKT, limit, cursor)
	if err != nil {
		api.writeStoreError(response, err)
		return
	}
	writeData(response, http.StatusOK, page)
}

func (api *API) revokeInstallation(response http.ResponseWriter, request *http.Request) {
	id := request.PathValue("id")
	if !uuidPattern.MatchString(id) || request.URL.RawQuery != "" || request.ContentLength != 0 || len(request.TransferEncoding) != 0 {
		writeError(response, http.StatusBadRequest, "protocol.invalid")
		return
	}
	principal, _ := auth.PrincipalFromContext(request.Context())
	deviceID, _ := request.Context().Value(deviceContextKey{}).(string)
	if err := api.database.RevokeInstallation(request.Context(), store.UserIdentity{Issuer: principal.Issuer, Subject: principal.Subject}, deviceID, principal.ProofKeyJKT, id); err != nil {
		api.writeStoreError(response, err)
		return
	}
	writeData(response, http.StatusOK, map[string]bool{"revoked": true})
}
