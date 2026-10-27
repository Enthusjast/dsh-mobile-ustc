package relay

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"dsh-mobile-ustc/services/remote/internal/store"
)

const privateOwnerHTTPPath = "/internal/relay/v1/http"
const relayOriginalPathHeader = "X-DSH-Relay-Original-Path"

type ownerHTTPForward struct{ cancel context.CancelFunc }

// An explicit method/path allowlist prevents the private listener becoming a
// general public API proxy. All original proofs are verified at the owner.
func OwnerHTTPResource(method, path string) (kind, id string) {
	for _, candidate := range []struct{ method, prefix, suffix, kind string }{
		{"POST", "/v1/approvals/", "/decisions", "approval"},
		{"GET", "/v1/host-files/", "/content", "host_file"},
		{"GET", "/v1/files/", "", "file_status"},
	} {
		if method != candidate.method || !strings.HasPrefix(path, candidate.prefix) || !strings.HasSuffix(path, candidate.suffix) {
			continue
		}
		id := strings.TrimSuffix(strings.TrimPrefix(path, candidate.prefix), candidate.suffix)
		if uuidPattern.MatchString(id) {
			return candidate.kind, id
		}
	}
	return "", ""
}

func (server *Server) OwnerHTTPRoutingEnabled() bool {
	return server.routing != nil && server.routing.ClientTLS != nil
}

func (server *Server) inspectPrivateRoute(request *http.Request) (store.RuntimeRoute, int, string) {
	if !server.OwnerHTTPRoutingEnabled() || request.URL.RawQuery != "" || request.URL.ForceQuery || request.URL.RawPath != "" || request.TLS == nil || len(request.TLS.VerifiedChains) == 0 || len(request.TLS.PeerCertificates) == 0 {
		return store.RuntimeRoute{}, http.StatusForbidden, "access.denied"
	}
	node, err := RelayCertificateNode(request.TLS.PeerCertificates[0])
	if err != nil || node != singleHeader(request, relayNodeHeader) {
		return store.RuntimeRoute{}, http.StatusForbidden, "access.denied"
	}
	if err := server.routing.Directory.ValidateRelayNode(request.Context(), node, singleHeader(request, relayGenerationHeader)); err != nil {
		return store.RuntimeRoute{}, http.StatusServiceUnavailable, "access.denied"
	}
	raw, err := base64.RawURLEncoding.DecodeString(singleHeader(request, relayRouteHeader))
	var route store.RuntimeRoute
	if err != nil || len(raw) > 4096 || decodePayload(raw, &route) != nil || route.RelayNode != server.routing.identity {
		return store.RuntimeRoute{}, http.StatusConflict, "runtime.changed"
	}
	return route, 0, ""
}

func (server *Server) servePrivateOwnerHTTP(response http.ResponseWriter, request *http.Request, owner http.Handler) {
	response.Header().Set("Cache-Control", "no-store")
	path := singleHeader(request, relayOriginalPathHeader)
	if kind, _ := OwnerHTTPResource(request.Method, path); kind == "" {
		writeError(response, http.StatusForbidden, "access.denied")
		return
	}
	route, status, code := server.inspectPrivateRoute(request)
	if status != 0 {
		writeError(response, status, code)
		return
	}
	if !server.currentDeviceRoute(request.Context(), route) {
		writeError(response, http.StatusConflict, "runtime.changed")
		return
	}
	// Restore only an allowlisted literal path. JWT/DPoP and file-read htu bind
	// the configured public origin plus this path, never caller proxy headers.
	copy := request.Clone(request.Context())
	value := *request.URL
	copy.URL = &value
	copy.URL.Path, copy.URL.RawPath = path, ""
	copy.RequestURI = path
	owner.ServeHTTP(response, copy)
}

func (server *Server) ForwardOwnerHTTP(response http.ResponseWriter, request *http.Request, runtime string) bool {
	if !server.OwnerHTTPRoutingEnabled() {
		return false
	}
	if kind, _ := OwnerHTTPResource(request.Method, request.URL.Path); kind == "" || request.URL.RawQuery != "" || request.URL.ForceQuery || request.URL.RawPath != "" {
		return false
	}
	route, err := server.routing.Directory.LookupRuntimeRoute(request.Context(), runtime)
	if errors.Is(err, store.ErrRuntimeConnectionStale) {
		return false
	}
	if err != nil {
		writeError(response, http.StatusServiceUnavailable, "internal")
		return true
	}
	if route.RelayNode == server.routing.identity {
		return false
	}
	if !store.ValidRelayOrigin(route.Origin) {
		writeError(response, http.StatusServiceUnavailable, "runtime.offline")
		return true
	}
	lifetime := 5 * time.Minute
	if request.Method == "POST" {
		lifetime = 8 * time.Second
	}
	ctx, cancel := context.WithTimeout(request.Context(), lifetime)
	forward := &ownerHTTPForward{cancel}
	server.mu.Lock()
	if server.draining || len(server.httpForwards) >= 128 {
		server.mu.Unlock()
		cancel()
		writeError(response, http.StatusServiceUnavailable, "rate.limited")
		return true
	}
	if server.httpForwards == nil {
		server.httpForwards = make(map[*ownerHTTPForward]struct{})
	}
	server.httpForwards[forward] = struct{}{}
	server.active.Add(1)
	server.mu.Unlock()
	defer func() {
		cancel()
		server.mu.Lock()
		delete(server.httpForwards, forward)
		server.mu.Unlock()
		server.active.Done()
	}()
	transport := server.routing.ownerTransport(route, nil)
	transport.ResponseHeaderTimeout = 8 * time.Second
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	privateURL, _ := url.Parse(route.Origin + privateOwnerHTTPPath)
	copy := request.Clone(ctx)
	copy.URL = privateURL
	copy.Host = privateURL.Host
	copy.RequestURI = ""
	copy.Header = make(http.Header)
	for _, name := range []string{"Authorization", "DPoP", "Content-Type", "X-DSH-File-Proof"} {
		if values := request.Header.Values(name); len(values) == 1 {
			copy.Header.Set(name, values[0])
		}
	}
	raw, _ := json.Marshal(route)
	copy.Header.Set(relayNodeHeader, server.routing.identity.NodeID)
	copy.Header.Set(relayGenerationHeader, server.routing.identity.Generation)
	copy.Header.Set(relayRouteHeader, base64.RawURLEncoding.EncodeToString(raw))
	copy.Header.Set(relayOriginalPathHeader, request.URL.Path)
	if request.Method == "POST" {
		if request.ContentLength > 16<<10 {
			writeError(response, http.StatusRequestEntityTooLarge, "protocol.invalid")
			return true
		}
		copy.Body = http.MaxBytesReader(response, request.Body, 16<<10)
		copy.GetBody = nil
	} else if request.ContentLength != 0 {
		writeError(response, http.StatusBadRequest, "protocol.invalid")
		return true
	}
	reply, err := client.Do(copy)
	if err != nil {
		writeError(response, http.StatusServiceUnavailable, "runtime.offline")
		return true
	}
	defer reply.Body.Close()
	for _, name := range []string{"Content-Type", "Content-Length", "Content-Disposition", "Content-Encoding", "X-Content-Type-Options", "X-DSH-Content-SHA256", "Cache-Control", "DPoP-Nonce", "WWW-Authenticate"} {
		if values := reply.Header.Values(name); len(values) == 1 {
			response.Header().Set(name, values[0])
		}
	}
	response.Header().Set("Cache-Control", "no-store")
	writer := http.NewResponseController(response)
	stop := context.AfterFunc(ctx, func() { _ = writer.SetWriteDeadline(time.Now()) })
	defer stop()
	response.WriteHeader(reply.StatusCode)
	buffer := make([]byte, 64<<10)
	for {
		count, readErr := reply.Body.Read(buffer)
		if count > 0 {
			_ = writer.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := response.Write(buffer[:count]); err != nil {
				return true
			}
		}
		if readErr == io.EOF {
			return true
		}
		if readErr != nil {
			panic(http.ErrAbortHandler)
		}
	}
}
