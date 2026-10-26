package httpapi

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/releases"
	"dsh-mobile-ustc/services/remote/internal/store"
)

func (api *API) appRelease(w http.ResponseWriter, r *http.Request) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query) != 4 {
		writeError(w, http.StatusBadRequest, "protocol.invalid")
		return
	}
	for _, key := range []string{"organization_id", "version_code", "protocol_version", "android_api"} {
		if len(query[key]) != 1 {
			writeError(w, http.StatusBadRequest, "protocol.invalid")
			return
		}
	}
	organization := query.Get("organization_id")
	parse := func(key string) int64 {
		raw := query.Get(key)
		value, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || strconv.FormatInt(value, 10) != raw {
			return 0
		}
		return value
	}
	request := releases.Request{VersionCode: parse("version_code"), ProtocolVersion: parse("protocol_version"), AndroidAPI: parse("android_api")}
	if !uuidPattern.MatchString(organization) || request.VersionCode < 1 || request.VersionCode > 9007199254740991 || request.ProtocolVersion != releases.ProtocolVersion || request.AndroidAPI < 26 || request.AndroidAPI > 100 {
		writeError(w, http.StatusBadRequest, "protocol.invalid")
		return
	}
	principal, _ := auth.PrincipalFromContext(r.Context())
	device, _ := r.Context().Value(deviceContextKey{}).(string)
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	user, err := api.database.AppReleaseAccess(ctx, store.UserIdentity{Issuer: principal.Issuer, Subject: principal.Subject}, device, principal.ProofKeyJKT, organization, principal.ExpiresAt)
	if err != nil {
		api.writeStoreError(w, err)
		return
	}
	selection, err := api.releases.Latest(releases.Actor{UserID: user, DeviceID: device, OrganizationID: organization}, request)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "update.unavailable")
		return
	}
	writeData(w, http.StatusOK, selection)
}
