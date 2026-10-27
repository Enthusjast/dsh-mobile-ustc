package httpapi

import (
	"context"
	"net/http"
	"strings"
	"time"

	"dsh-mobile-ustc/services/remote/internal/files"
	"dsh-mobile-ustc/services/remote/internal/relay"
	"dsh-mobile-ustc/services/remote/internal/store"
)

type ownerRoutingRepository interface {
	ApprovalRuntimeForRouting(context.Context, store.UserIdentity, string, string) (string, error)
	HostFileForRouting(context.Context, string, string) (store.HostFileRouteInspection, error)
}

func (api *API) forwardOwnerRequest(response http.ResponseWriter, request *http.Request) bool {
	if !api.realtime.OwnerHTTPRoutingEnabled() {
		return false
	}
	kind, id := relay.OwnerHTTPResource(request.Method, request.URL.Path)
	if kind == "" || request.URL.RawQuery != "" || request.URL.ForceQuery || request.URL.RawPath != "" {
		return false
	}
	repository, ok := api.database.(ownerRoutingRepository)
	if !ok {
		return false
	}
	ctx, cancel := context.WithTimeout(request.Context(), 2*time.Second)
	defer cancel()
	inspectionRequest := request.WithContext(ctx)
	var runtime string
	if kind == "host_file" {
		values := request.Header.Values("Authorization")
		if len(values) != 1 || len(request.Header.Values("X-DSH-File-Proof")) != 1 {
			return false
		}
		scheme, token, ok := strings.Cut(values[0], " ")
		if !ok || scheme != "DSH-File" {
			return false
		}
		inspection, err := repository.HostFileForRouting(ctx, id, token)
		if err != nil || api.identity.VerifyFileReadProof(inspectionRequest, request.Header.Get("X-DSH-File-Proof"), inspection.PublicJWK, inspection.Expected) != nil {
			return false
		}
		runtime = inspection.Expected.RuntimeID
	} else {
		principal, err := api.identity.InspectRequestForRouting(inspectionRequest)
		if err != nil {
			return false
		}
		if _, host := api.hostClients[principal.ClientID]; host {
			return false
		}
		identity := store.UserIdentity{Issuer: principal.Issuer, Subject: principal.Subject}
		if kind == "approval" {
			if api.realtime == nil {
				return false
			}
			runtime, err = repository.ApprovalRuntimeForRouting(ctx, identity, principal.ProofKeyJKT, id)
			if err != nil {
				return false
			}
		} else {
			if api.files == nil {
				return false
			}
			device, err := api.database.ActiveDevice(ctx, identity, principal.ProofKeyJKT)
			if err != nil {
				return false
			}
			status, err := api.files.Status(ctx, files.Actor{Issuer: principal.Issuer, Subject: principal.Subject, DeviceID: device, ProofKeyJKT: principal.ProofKeyJKT}, id)
			if err != nil {
				return false
			}
			runtime = status.RuntimeID
		}
	}
	return api.realtime.ForwardOwnerHTTP(response, request, runtime)
}
