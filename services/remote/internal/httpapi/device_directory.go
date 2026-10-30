package httpapi

import (
	"net/http"
	"net/url"
	"strconv"

	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/store"
)

func (api *API) listDevices(response http.ResponseWriter, request *http.Request) {
	query, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil || request.ContentLength != 0 || len(request.TransferEncoding) != 0 {
		writeError(response, http.StatusBadRequest, "protocol.invalid")
		return
	}
	limit, cursor := 50, ""
	for key, values := range query {
		if len(values) != 1 || values[0] == "" {
			writeError(response, http.StatusBadRequest, "protocol.invalid")
			return
		}
		switch key {
		case "limit":
			limit, err = strconv.Atoi(values[0])
			if err != nil || limit < 1 || limit > 100 || strconv.Itoa(limit) != values[0] {
				writeError(response, http.StatusBadRequest, "protocol.invalid")
				return
			}
		case "cursor":
			cursor = values[0]
			if len(cursor) > 1024 {
				writeError(response, http.StatusBadRequest, "protocol.invalid")
				return
			}
		default:
			writeError(response, http.StatusBadRequest, "protocol.invalid")
			return
		}
	}
	principal, _ := auth.PrincipalFromContext(request.Context())
	deviceID, _ := request.Context().Value(deviceContextKey{}).(string)
	page, err := api.database.ListDevices(request.Context(), store.UserIdentity{Issuer: principal.Issuer, Subject: principal.Subject}, deviceID, principal.ProofKeyJKT, limit, cursor)
	if err != nil {
		api.writeStoreError(response, err)
		return
	}
	writeData(response, http.StatusOK, page)
}
