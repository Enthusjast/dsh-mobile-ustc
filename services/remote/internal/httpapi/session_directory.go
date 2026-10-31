package httpapi

import (
	"context"
	"net/http"
	"net/url"

	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/store"
)

type sessionNamesRepository interface {
	SessionDirectoryNames(context.Context, store.UserIdentity, string, string, string, int, string) (store.SessionDirectory, error)
}

func sessionDirectoryPageQuery(request *http.Request) (int, string, bool, bool) {
	query, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil { return 0, "", false, false }
	names := false
	if values, exists := query["projection"]; exists {
		if len(values) != 1 || values[0] != "names.v1" { return 0, "", false, false }
		names = true
		query.Del("projection")
	}
	copyRequest := request.Clone(request.Context())
	copyRequest.URL.RawQuery = query.Encode()
	limit, cursor, ok := directoryPageQuery(copyRequest)
	return limit, cursor, names, ok
}

func (api *API) sessionDirectory(w http.ResponseWriter, r *http.Request) {
	limit, cursor, names, ok := sessionDirectoryPageQuery(r)
	id := r.PathValue("id")
	if !ok || !uuidPattern.MatchString(id) {
		writeError(w, http.StatusBadRequest, "protocol.invalid")
		return
	}
	principal, _ := auth.PrincipalFromContext(r.Context())
	device, _ := r.Context().Value(deviceContextKey{}).(string)
	identity := store.UserIdentity{Issuer: principal.Issuer, Subject: principal.Subject}
	var page store.SessionDirectory
	var err error
	if names {
		repository, supported := api.database.(sessionNamesRepository)
		if !supported { writeError(w, http.StatusServiceUnavailable, "protocol.unsupported"); return }
		page, err = repository.SessionDirectoryNames(r.Context(), identity, device, principal.ProofKeyJKT, id, limit, cursor)
	} else {
		page, err = api.database.SessionDirectory(r.Context(), identity, device, principal.ProofKeyJKT, id, limit, cursor)
	}
	if err != nil {
		api.writeStoreError(w, err)
		return
	}
	writeData(w, http.StatusOK, page)
}
