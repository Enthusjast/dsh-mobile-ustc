package httpapi

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/files"
)

func (api *API) hostFileContent(response http.ResponseWriter, request *http.Request) {
	id := request.PathValue("id")
	if !uuidPattern.MatchString(id) || request.URL.RawQuery != "" || request.URL.ForceQuery || len(request.Header.Values("Authorization")) != 1 || len(request.Header.Values("X-DSH-File-Proof")) != 1 {
		writeError(response, http.StatusUnauthorized, "file.read_invalid")
		return
	}
	scheme, token, ok := strings.Cut(request.Header.Get("Authorization"), " ")
	if !ok || scheme != "DSH-File" || len(token) != 43 {
		writeError(response, http.StatusUnauthorized, "file.read_invalid")
		return
	}
	stream, err := api.fileHandoffs.Open(request.Context(), id, token, func(permit files.ReadPermit) error {
		identity := permit.Handoff.Host
		return api.identity.VerifyFileReadProof(request, request.Header.Get("X-DSH-File-Proof"), permit.PublicJWK, auth.FileReadExpectation{
			InstallationID: identity.InstallationID, KeyThumbprint: permit.KeyThumbprint, RuntimeID: identity.RuntimeID, RuntimeEpoch: identity.RuntimeEpoch, ConnectionID: identity.ConnectionID, HandoffID: id, FileID: permit.Handoff.File.ID, Token: token})
	}, api.realtime.FileHostLifetime)
	if err != nil {
		api.writeStoreError(response, err)
		return
	}
	defer stream.Close()
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/octet-stream")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("Content-Length", strconv.FormatInt(stream.Handoff.File.SizeBytes, 10))
	writer := http.NewResponseController(response)
	buffer := make([]byte, files.ChunkBytes)
	for {
		count, readErr := stream.Read(buffer)
		if count > 0 {
			_ = writer.SetWriteDeadline(time.Now().Add(30 * time.Second))
			if _, err := response.Write(buffer[:count]); err != nil {
				return
			}
		}
		if readErr == io.EOF {
			return
		}
		if readErr != nil {
			panic(http.ErrAbortHandler)
		}
	}
}
