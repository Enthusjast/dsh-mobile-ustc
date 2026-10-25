package httpapi

import (
	"context"
	"io"
	"log"
	"mime"
	"net/http"
	"strconv"
	"time"

	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/files"
)

func (api *API) exportStatus(response http.ResponseWriter, request *http.Request) {
	id := request.PathValue("id")
	if !uuidPattern.MatchString(id) {
		writeError(response, http.StatusBadRequest, "protocol.invalid")
		return
	}
	ctx, cancel, actor, ok := fileOperation(response, request)
	if !ok {
		return
	}
	defer cancel()
	status, err := api.fileExports.Status(ctx, actor, id)
	if err != nil {
		api.writeStoreError(response, err)
		return
	}
	writeData(response, http.StatusOK, map[string]any{"file": status})
}

func (api *API) exportContent(response http.ResponseWriter, request *http.Request) {
	id := request.PathValue("id")
	if !uuidPattern.MatchString(id) || request.Header.Get("Range") != "" || request.URL.RawQuery != "" || request.URL.ForceQuery {
		writeError(response, http.StatusBadRequest, "protocol.invalid")
		return
	}
	principal, ok := auth.PrincipalFromContext(request.Context())
	device, _ := request.Context().Value(deviceContextKey{}).(string)
	if !ok || device == "" || !principal.ExpiresAt.After(time.Now()) {
		writeError(response, http.StatusUnauthorized, "auth.expired")
		return
	}
	until := time.Now().Add(5 * time.Minute)
	if principal.ExpiresAt.Before(until) {
		until = principal.ExpiresAt
	}
	ctx, cancel := context.WithDeadline(request.Context(), until)
	defer cancel()
	stream, err := api.fileExports.Open(ctx, files.Actor{Issuer: principal.Issuer, Subject: principal.Subject, DeviceID: device, ProofKeyJKT: principal.ProofKeyJKT}, id)
	if err != nil {
		api.writeStoreError(response, err)
		return
	}
	defer func() {
		if err := stream.Close(); err != nil {
			log.Print("remote export download audit unavailable")
		}
	}()
	response.Header().Set("Cache-Control", "no-store, no-transform")
	response.Header().Set("Content-Type", "application/octet-stream")
	response.Header().Set("Content-Encoding", "identity")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": stream.File.Name}))
	response.Header().Set("Content-Length", strconv.FormatInt(stream.File.SizeBytes, 10))
	response.Header().Set("X-DSH-Content-SHA256", stream.File.SHA256)
	writer := http.NewResponseController(response)
	stop := context.AfterFunc(stream.Context(), func() { _ = writer.SetWriteDeadline(time.Now()) })
	defer stop()
	buffer := make([]byte, files.ChunkBytes)
	for {
		count, readErr := stream.Read(buffer)
		if count > 0 {
			_ = writer.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if stream.Context().Err() != nil {
				panic(http.ErrAbortHandler)
			}
			if _, err := response.Write(buffer[:count]); err != nil {
				return
			}
		}
		if readErr == io.EOF {
			if err := stream.Complete(); err != nil {
				panic(http.ErrAbortHandler)
			}
			return
		}
		if readErr != nil {
			panic(http.ErrAbortHandler)
		}
	}
}
