package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"dsh-mobile-ustc/services/remote/internal/approval"
	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/files"
	"dsh-mobile-ustc/services/remote/internal/observability"
	"dsh-mobile-ustc/services/remote/internal/relay"
	"dsh-mobile-ustc/services/remote/internal/releases"
	"dsh-mobile-ustc/services/remote/internal/store"
)

const maxJSONRequestBytes = 16 << 10

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type Repository interface {
	Ready(context.Context) error
	AccountIdentity(context.Context, store.UserIdentity) (store.AccountIdentity, error)
	AppReleaseAccess(context.Context, store.UserIdentity, string, string, string, time.Time) (string, error)
	CurrentDevice(context.Context, store.UserIdentity, string) (store.CurrentDevice, error)
	ListDevices(context.Context, store.UserIdentity, string, string, int, string) (store.DeviceDirectory, error)
	ListInstallations(context.Context, store.UserIdentity, string, string, int, string) (store.InstallationDirectory, error)
	ListInstallationRuntimes(context.Context, store.UserIdentity, string, string, string, int, string) (store.InstallationRuntimeDirectory, error)
	RevokeInstallationRuntime(context.Context, store.UserIdentity, string, string, string, string) error
	ListRuntimeGrants(context.Context, store.UserIdentity, string, string, string, int, string) (store.RuntimeGrantDirectory, error)
	RevokeInstallation(context.Context, store.UserIdentity, string, string, string) error
	ActiveDevice(context.Context, store.UserIdentity, string) (string, error)
	CreateEnrollment(context.Context, store.EnrollmentInput) (store.EnrollmentCreated, error)
	GetEnrollment(context.Context, store.UserIdentity, string) (store.EnrollmentInfo, error)
	PreviewEnrollment(context.Context, store.UserIdentity, string, string) (store.EnrollmentInfo, error)
	ConfirmEnrollmentUser(context.Context, store.UserIdentity, string, string, string, string) (store.EnrollmentConfirmation, error)
	ConfirmEnrollmentHost(context.Context, store.UserIdentity, string, string, string, string) (store.EnrollmentConfirmation, error)
	CreateHostCredentialChallenge(context.Context, store.UserIdentity, string) (store.HostCredentialChallenge, error)
	ExchangeHostCredential(context.Context, store.UserIdentity, string, string, string) (store.HostConnectionCredential, error)
	RegisterDevice(context.Context, store.DeviceRegistration) (string, error)
	RevokeDevice(context.Context, string, string, string) error
	PutRuntimeGrant(context.Context, store.UserIdentity, string, string, string, string, store.RuntimeGrantInput) (int64, error)
	RevokeRuntimeGrant(context.Context, store.UserIdentity, string, string, string, string) (int64, error)
	IssueRealtimeTicket(context.Context, store.UserIdentity, string, string, store.GrantScope) (store.RealtimeTicket, error)
	PrepareRealtimeTicket(context.Context, string) (store.TicketRedemption, error)
	ConsumeRealtimeTicket(context.Context, string) (store.TicketRedemption, error)
	ValidateRealtimeLease(context.Context, store.TicketRedemption) error
	AuthorizeRealtimeCommandReceipt(context.Context, store.TicketRedemption, store.CommandStatus) error
	LookupHostConnectionCredential(context.Context, string) (store.HostCredentialIdentity, error)
	AttachRuntimeConnection(context.Context, store.RuntimeConnectionInput) (store.RuntimeConnection, error)
	TouchRuntimeConnection(context.Context, string, string, string, string) error
	DetachRuntimeConnection(context.Context, string, string, string, string) error
	RecordRealtimeCommand(context.Context, store.TicketRedemption, string, string, string, string) (store.CommandStatus, error)
	RecordRealtimeSessionCreate(context.Context, store.TicketRedemption, string, string, string) (store.CommandStatus, error)
	RecordRealtimeSessionFork(context.Context, store.TicketRedemption, string, string, string, string) (store.CommandStatus, error)
	AuthorizeRealtimeSessionFork(context.Context, store.TicketRedemption, string, string) error
	RecordRealtimeCommandReceipt(context.Context, store.RelayCommandReceipt) (store.CommandStatus, error)
	MarkRealtimeCommandUnknown(context.Context, store.TicketRedemption, string, string, string) (store.CommandStatus, error)
	SyncRealtimeSessionCatalog(context.Context, store.RuntimeConnection, int64, bool, []store.SessionCatalogItem) error
	AuthorizeRealtimeSessionRead(context.Context, store.TicketRedemption, string) error
	AuthorizeRealtimeQuestion(context.Context, store.TicketRedemption, string) error
	InvalidRealtimeConnectionLeases(context.Context, []store.RealtimeConnectionLease) ([]string, error)
	ListHosts(context.Context, store.UserIdentity) ([]store.Host, error)
	HostDirectory(context.Context, store.UserIdentity, string, string, int, string) (store.HostDirectory, error)
	RuntimeDirectory(context.Context, store.UserIdentity, string, string, int, string) (store.RuntimeDirectory, error)
	ListRuntimes(context.Context, store.UserIdentity) ([]store.Runtime, error)
	ListSessions(context.Context, store.UserIdentity, string) ([]store.Session, error)
	SessionDirectory(context.Context, store.UserIdentity, string, string, string, int, string) (store.SessionDirectory, error)
	PhoneApprovalStatus(context.Context, store.UserIdentity, string, string, string) (store.ApprovalStatus, error)
	SessionCacheReadAccess(context.Context, store.UserIdentity, string, string, string, string, time.Time) (store.SessionReadAccess, error)
	SessionReadTarget(context.Context, store.UserIdentity, string, string, string, string, time.Time) (store.SessionTarget, error)
	QuestionAnswerStatus(context.Context, store.UserIdentity, string, string, string, string, string, time.Time) (store.CommandStatus, error)
	CommandStatus(context.Context, store.UserIdentity, string, string) (store.CommandStatus, error)
}

type API struct {
	database     Repository
	identity     *auth.Authenticator
	hostClients  map[string]struct{}
	realtime     *relay.Server
	files        *files.Service
	fileHandoffs *files.Handoffs
	fileExports  *files.Exports
	push         *store.PushStore
	releases     *releases.Catalog
}

type Handler struct {
	router   http.Handler
	realtime *relay.Server
	api      *API
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if handler.api != nil && handler.api.forwardOwnerRequest(response, request) {
		return
	}
	handler.router.ServeHTTP(response, request)
}

func (handler *Handler) Drain(ctx context.Context) error {
	return handler.realtime.Drain(ctx)
}

func (handler *Handler) ApplyControlEvent(ctx context.Context, event store.ControlEvent) error {
	return handler.realtime.ApplyControlEvent(ctx, event)
}

func (handler *Handler) RevalidateConnections(ctx context.Context) error {
	return handler.realtime.RevalidateConnections(ctx)
}

func (handler *Handler) ConfigurePendingHandshakes(limit int) error {
	return handler.realtime.ConfigurePendingHandshakes(limit)
}

func (handler *Handler) ConfigureRouting(config relay.RoutingConfig) error {
	return handler.realtime.ConfigureRouting(config)
}

func (handler *Handler) PrivateRelayHandler() http.Handler {
	return handler.realtime.PrivateRelayHandler(handler.router)
}

type deviceContextKey struct{}

type Config struct {
	HostClientIDs []string
	Approvals     *relay.ApprovalConfig
	Files         *files.Service
	FileHandoffs  *files.Handoffs
	FileExports   *files.Exports
	Push          *store.PushStore
	Releases      *releases.Catalog
	Metrics       *observability.Metrics
}

type deviceRequest struct {
	Name              string          `json:"name"`
	ApprovalPublicJWK json.RawMessage `json:"approval_public_jwk"`
	ApprovalProof     string          `json:"approval_proof"`
	ProofPublicJWK    json.RawMessage `json:"proof_public_jwk"`
}

type enrollmentRequest struct {
	RequestID             string          `json:"request_id"`
	OrganizationID        string          `json:"organization_id"`
	HostID                string          `json:"host_id,omitempty"`
	Alias                 string          `json:"alias"`
	ProfileRef            string          `json:"profile_ref"`
	DSHVersion            string          `json:"dsh_version"`
	ApplicationVersion    string          `json:"application_version"`
	PluginVersion         string          `json:"plugin_version"`
	ProtocolVersion       int             `json:"protocol_version"`
	InstallationPublicJWK json.RawMessage `json:"installation_public_jwk"`
	Code                  string          `json:"code"`
	WorkspaceRefs         *[]string       `json:"workspace_refs"`
}

type enrollmentCodeRequest struct {
	Code string `json:"code"`
}

type enrollmentHostConfirmationRequest struct {
	Code            string `json:"code"`
	ConfirmedUserID string `json:"confirmed_user_id"`
}

type hostCredentialExchangeRequest struct {
	ChallengeID string `json:"challenge_id"`
	Proof       string `json:"proof"`
}

func New(database Repository, identity *auth.Authenticator, configs ...Config) *Handler {
	api := &API{database: database, identity: identity, hostClients: make(map[string]struct{})}
	if len(configs) > 0 {
		for _, id := range configs[0].HostClientIDs {
			if strings.TrimSpace(id) != "" {
				api.hostClients[id] = struct{}{}
			}
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", api.health)
	mux.HandleFunc("GET /readyz", api.ready)
	mux.Handle("GET /v1/me", api.authenticated(http.HandlerFunc(api.me)))
	if len(configs) > 0 && configs[0].Releases != nil {
		api.releases = configs[0].Releases
		mux.Handle("GET /v1/app/releases/latest", api.protected(http.HandlerFunc(api.appRelease)))
	}
	mux.Handle("POST /v1/devices", api.phoneAuthenticated(http.HandlerFunc(api.registerDevice)))
	mux.Handle("GET /v1/devices", api.protected(http.HandlerFunc(api.listDevices)))
	mux.Handle("GET /v1/installations", api.protected(http.HandlerFunc(api.listInstallations)))
	mux.Handle("GET /v1/installations/{id}/runtimes", api.protected(http.HandlerFunc(api.listInstallationRuntimes)))
	mux.Handle("DELETE /v1/installations/{id}/runtimes/{runtime_id}", api.protected(http.HandlerFunc(api.revokeInstallationRuntime)))
	mux.Handle("DELETE /v1/installations/{id}", api.protected(http.HandlerFunc(api.revokeInstallation)))
	mux.Handle("GET /v1/devices/current", api.phoneAuthenticated(http.HandlerFunc(api.currentDevice)))
	mux.Handle("POST /v1/enrollments", api.hostAuthenticated(http.HandlerFunc(api.createEnrollment)))
	mux.Handle("GET /v1/enrollments/{id}", api.authenticated(http.HandlerFunc(api.getEnrollment)))
	mux.Handle("GET /v1/enrollments/{id}/host-review", api.hostAuthenticated(http.HandlerFunc(api.reviewEnrollmentHost)))
	mux.Handle("POST /v1/enrollments/{id}/preview", api.protected(http.HandlerFunc(api.previewEnrollment)))
	mux.Handle("POST /v1/enrollments/{id}/confirm", api.protected(http.HandlerFunc(api.confirmEnrollmentUser)))
	mux.Handle("POST /v1/enrollments/{id}/host-confirm", api.hostAuthenticated(http.HandlerFunc(api.confirmEnrollmentHost)))
	mux.Handle("POST /v1/host-credentials/challenges", api.hostAuthenticated(http.HandlerFunc(api.createHostCredentialChallenge)))
	mux.Handle("POST /v1/host-credentials", api.hostAuthenticated(http.HandlerFunc(api.exchangeHostCredential)))
	mux.Handle("DELETE /v1/devices/{id}", api.protected(http.HandlerFunc(api.revokeDevice)))
	mux.Handle("GET /v1/hosts", api.protected(http.HandlerFunc(api.listHosts)))
	mux.Handle("GET /v1/host-directory", api.protected(http.HandlerFunc(api.hostDirectory)))
	mux.Handle("GET /v1/runtime-directory", api.protected(http.HandlerFunc(api.runtimeDirectory)))
	mux.Handle("GET /v1/runtimes", api.protected(http.HandlerFunc(api.listRuntimes)))
	mux.Handle("GET /v1/runtimes/{id}/sessions", api.protected(http.HandlerFunc(api.listSessions)))
	mux.Handle("GET /v1/runtimes/{id}/session-directory", api.protected(http.HandlerFunc(api.sessionDirectory)))
	mux.Handle("GET /v1/runtimes/{id}/sessions/{session_id}", api.protected(http.HandlerFunc(api.sessionTarget)))
	mux.Handle("GET /v1/runtimes/{id}/sessions/{session_id}/question-answers/{request_id}", api.protected(http.HandlerFunc(api.questionAnswerStatus)))
	mux.Handle("GET /v1/runtimes/{id}/sessions/{session_id}/read-access", api.protected(http.HandlerFunc(api.sessionReadAccess)))
	mux.Handle("GET /v1/runtimes/{id}/grants", api.protected(http.HandlerFunc(api.listRuntimeGrants)))
	mux.Handle("PUT /v1/runtimes/{id}/grants/{user_id}", api.protected(http.HandlerFunc(api.putRuntimeGrant)))
	mux.Handle("DELETE /v1/runtimes/{id}/grants/{user_id}", api.protected(http.HandlerFunc(api.revokeRuntimeGrant)))
	mux.Handle("POST /v1/realtime/tickets", api.protected(http.HandlerFunc(api.issueRealtimeTicket)))
	var approvalConfig []relay.ApprovalConfig
	if len(configs) > 0 && configs[0].Approvals != nil {
		approvalConfig = append(approvalConfig, *configs[0].Approvals)
	}
	realtime := relay.New(database, approvalConfig...)
	if len(configs) > 0 {
		realtime.ConfigureMetrics(configs[0].Metrics)
	}
	api.realtime = realtime
	mux.Handle("GET /v1/realtime", realtime)
	if len(approvalConfig) > 0 && approvalConfig[0].Control != nil && approvalConfig[0].Leases != nil {
		mux.Handle("POST /v1/approvals/{id}/decisions", api.protected(http.HandlerFunc(api.decideApproval)))
	}
	mux.Handle("GET /v1/approvals/{id}", api.protected(http.HandlerFunc(api.approvalStatus)))
	mux.Handle("GET /v1/commands/{id}", api.protected(http.HandlerFunc(api.commandStatus)))
	if len(configs) > 0 && configs[0].Push != nil {
		api.push = configs[0].Push
		mux.Handle("GET /v1/push/capabilities", api.protected(http.HandlerFunc(api.pushCapabilities)))
		mux.Handle("POST /v1/push-bindings", api.protected(http.HandlerFunc(api.pushRegister)))
		mux.Handle("GET /v1/push-bindings/{id}", api.protected(http.HandlerFunc(api.pushStatus)))
		mux.Handle("POST /v1/push-bindings/{id}/confirm", api.protected(http.HandlerFunc(api.pushConfirm)))
		mux.Handle("POST /v1/push-bindings/{id}/lease", api.protected(http.HandlerFunc(api.pushRenew)))
		mux.HandleFunc("DELETE /v1/push-bindings/{id}", api.pushRevoke)
		mux.Handle("GET /v1/notifications", api.protected(http.HandlerFunc(api.pushInbox)))
		mux.Handle("GET /v1/notifications/{id}", api.protected(http.HandlerFunc(api.pushReference)))
		mux.Handle("POST /v1/notifications/{id}/receipts", api.protected(http.HandlerFunc(api.pushReceipt)))
	}
	if len(configs) > 0 && configs[0].Files != nil {
		api.files = configs[0].Files
		mux.Handle("POST /v1/runtimes/{id}/sessions/{session_id}/files", api.protected(http.HandlerFunc(api.registerFile)))
		mux.Handle("GET /v1/files/{id}", api.protected(http.HandlerFunc(api.fileStatus)))
		mux.Handle("POST /v1/files/{id}/upload-url", api.protected(http.HandlerFunc(api.fileUploadURL)))
		mux.Handle("POST /v1/files/{id}/commit", api.protected(http.HandlerFunc(api.commitFile)))
		if configs[0].FileExports != nil {
			api.fileExports = configs[0].FileExports
			realtime.EnableExports(api.fileExports)
			mux.Handle("GET /v1/file-exports/{id}", api.protected(http.HandlerFunc(api.exportStatus)))
			mux.Handle("GET /v1/files/{id}/content", api.protected(http.HandlerFunc(api.exportContent)))
		}
		if configs[0].FileHandoffs != nil {
			api.fileHandoffs = configs[0].FileHandoffs
			realtime.EnableFiles(api.fileHandoffs)
			mux.HandleFunc("GET /v1/host-files/{id}/content", api.hostFileContent)
		}
	}
	return &Handler{router: mux, realtime: realtime, api: api}
}

func (api *API) protected(next http.Handler) http.Handler {
	return api.phoneAuthenticated(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		principal, _ := auth.PrincipalFromContext(request.Context())
		deviceID, err := api.database.ActiveDevice(request.Context(), store.UserIdentity{Issuer: principal.Issuer, Subject: principal.Subject}, principal.ProofKeyJKT)
		if err != nil {
			api.writeStoreError(response, err)
			return
		}
		ctx := context.WithValue(request.Context(), deviceContextKey{}, deviceID)
		next.ServeHTTP(response, request.WithContext(ctx))
	}))
}

func (api *API) authenticated(next http.Handler) http.Handler {
	return api.identity.Middleware(next)
}

func (api *API) phoneAuthenticated(next http.Handler) http.Handler {
	return api.authenticated(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		principal, _ := auth.PrincipalFromContext(request.Context())
		if _, host := api.hostClients[principal.ClientID]; host {
			writeError(response, http.StatusForbidden, "access.denied")
			return
		}
		next.ServeHTTP(response, request)
	}))
}

func (api *API) hostAuthenticated(next http.Handler) http.Handler {
	return api.authenticated(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		principal, _ := auth.PrincipalFromContext(request.Context())
		if _, ok := api.hostClients[principal.ClientID]; !ok {
			writeError(response, http.StatusForbidden, "access.denied")
			return
		}
		next.ServeHTTP(response, request)
	}))
}

func (api *API) createEnrollment(response http.ResponseWriter, request *http.Request) {
	var input enrollmentRequest
	if !decodeBody(response, request, &input) || !uuidPattern.MatchString(input.RequestID) ||
		!uuidPattern.MatchString(input.OrganizationID) || input.WorkspaceRefs == nil ||
		input.HostID != "" && !uuidPattern.MatchString(input.HostID) {
		writeError(response, http.StatusBadRequest, "protocol.invalid")
		return
	}
	keyThumbprint, err := auth.PublicP256JWKThumbprintJSON(input.InstallationPublicJWK)
	if err != nil {
		writeError(response, http.StatusBadRequest, "device.key_invalid")
		return
	}
	principal, _ := auth.PrincipalFromContext(request.Context())
	if keyThumbprint != principal.ProofKeyJKT {
		writeError(response, http.StatusForbidden, "access.denied")
		return
	}
	enrollmentInput, _, _, err := store.NormalizeEnrollmentInput(store.EnrollmentInput{
		Issuer: principal.Issuer, Subject: principal.Subject,
		RequestID: input.RequestID, OrganizationID: input.OrganizationID, HostID: input.HostID, Alias: input.Alias,
		ProfileRef: input.ProfileRef, DSHVersion: input.DSHVersion,
		ApplicationVersion: input.ApplicationVersion, PluginVersion: input.PluginVersion,
		ProtocolVersion: input.ProtocolVersion, InstallationPublicJWK: input.InstallationPublicJWK,
		InstallationKeyThumbprint: keyThumbprint, Code: input.Code, WorkspaceRefs: *input.WorkspaceRefs,
	})
	if err != nil {
		writeError(response, http.StatusBadRequest, "enrollment.invalid")
		return
	}
	enrollment, err := api.database.CreateEnrollment(request.Context(), enrollmentInput)
	if err != nil {
		api.writeStoreError(response, err)
		return
	}
	writeData(response, http.StatusCreated, enrollment)
}

func (api *API) getEnrollment(response http.ResponseWriter, request *http.Request) {
	enrollmentID := request.PathValue("id")
	if !uuidPattern.MatchString(enrollmentID) {
		writeError(response, http.StatusBadRequest, "protocol.invalid")
		return
	}
	principal, _ := auth.PrincipalFromContext(request.Context())
	_, hostClient := api.hostClients[principal.ClientID]
	if !hostClient {
		if _, err := api.database.ActiveDevice(request.Context(), store.UserIdentity{Issuer: principal.Issuer, Subject: principal.Subject}, principal.ProofKeyJKT); err != nil {
			api.writeStoreError(response, err)
			return
		}
	}
	info, err := api.database.GetEnrollment(request.Context(), store.UserIdentity{Issuer: principal.Issuer, Subject: principal.Subject}, enrollmentID)
	if err != nil {
		api.writeStoreError(response, err)
		return
	}
	if hostClient && info.InstallationKeyJKT != principal.ProofKeyJKT {
		writeError(response, http.StatusForbidden, "access.denied")
		return
	}
	writeData(response, http.StatusOK, info)
}

func (api *API) reviewEnrollmentHost(response http.ResponseWriter, request *http.Request) {
	enrollmentID := request.PathValue("id")
	if !uuidPattern.MatchString(enrollmentID) || request.URL.RawQuery != "" {
		writeError(response, http.StatusBadRequest, "protocol.invalid")
		return
	}
	principal, _ := auth.PrincipalFromContext(request.Context())
	info, err := api.database.GetEnrollment(request.Context(), store.UserIdentity{Issuer: principal.Issuer, Subject: principal.Subject}, enrollmentID)
	if err != nil {
		api.writeStoreError(response, err)
		return
	}
	if !info.HostReviewOwner || !info.HostReviewTargetActive || info.InstallationKeyJKT != principal.ProofKeyJKT {
		writeError(response, http.StatusForbidden, "access.denied")
		return
	}
	writeData(response, http.StatusOK, store.EnrollmentHostReview{Enrollment: info, ConfirmedUser: info.HostReviewUser})
}

func (api *API) confirmEnrollmentUser(response http.ResponseWriter, request *http.Request) {
	api.confirmEnrollment(response, request, false)
}

func (api *API) previewEnrollment(response http.ResponseWriter, request *http.Request) {
	enrollmentID := request.PathValue("id")
	if !uuidPattern.MatchString(enrollmentID) {
		writeError(response, http.StatusBadRequest, "protocol.invalid")
		return
	}
	var input enrollmentCodeRequest
	if !decodeBody(response, request, &input) {
		writeError(response, http.StatusBadRequest, "enrollment.invalid")
		return
	}
	principal, _ := auth.PrincipalFromContext(request.Context())
	info, err := api.database.PreviewEnrollment(request.Context(), store.UserIdentity{Issuer: principal.Issuer, Subject: principal.Subject}, enrollmentID, input.Code)
	if err != nil {
		api.writeStoreError(response, err)
		return
	}
	writeData(response, http.StatusOK, info)
}

func (api *API) confirmEnrollmentHost(response http.ResponseWriter, request *http.Request) {
	api.confirmEnrollment(response, request, true)
}

func (api *API) confirmEnrollment(response http.ResponseWriter, request *http.Request, hostConfirmation bool) {
	enrollmentID := request.PathValue("id")
	if !uuidPattern.MatchString(enrollmentID) {
		writeError(response, http.StatusBadRequest, "protocol.invalid")
		return
	}
	var code, confirmedUserID string
	if hostConfirmation {
		var input enrollmentHostConfirmationRequest
		if !decodeBody(response, request, &input) || !uuidPattern.MatchString(input.ConfirmedUserID) {
			writeError(response, http.StatusBadRequest, "enrollment.invalid")
			return
		}
		code, confirmedUserID = input.Code, input.ConfirmedUserID
	} else {
		var input enrollmentCodeRequest
		if !decodeBody(response, request, &input) {
			writeError(response, http.StatusBadRequest, "enrollment.invalid")
			return
		}
		code = input.Code
	}
	principal, _ := auth.PrincipalFromContext(request.Context())
	var confirmation store.EnrollmentConfirmation
	var err error
	if hostConfirmation {
		confirmation, err = api.database.ConfirmEnrollmentHost(request.Context(),
			store.UserIdentity{Issuer: principal.Issuer, Subject: principal.Subject},
			principal.ProofKeyJKT, enrollmentID, code, confirmedUserID)
	} else {
		deviceID, _ := request.Context().Value(deviceContextKey{}).(string)
		confirmation, err = api.database.ConfirmEnrollmentUser(request.Context(),
			store.UserIdentity{Issuer: principal.Issuer, Subject: principal.Subject},
			deviceID, principal.ProofKeyJKT, enrollmentID, code)
	}
	if err != nil {
		api.writeStoreError(response, err)
		return
	}
	writeData(response, http.StatusOK, confirmation)
}

func (api *API) createHostCredentialChallenge(response http.ResponseWriter, request *http.Request) {
	principal, _ := auth.PrincipalFromContext(request.Context())
	challenge, err := api.database.CreateHostCredentialChallenge(request.Context(),
		store.UserIdentity{Issuer: principal.Issuer, Subject: principal.Subject}, principal.ProofKeyJKT)
	if err != nil {
		api.writeStoreError(response, err)
		return
	}
	writeData(response, http.StatusCreated, challenge)
}

func (api *API) exchangeHostCredential(response http.ResponseWriter, request *http.Request) {
	var input hostCredentialExchangeRequest
	if !decodeBody(response, request, &input) || !uuidPattern.MatchString(input.ChallengeID) || input.Proof == "" || len(input.Proof) > 8<<10 {
		writeError(response, http.StatusBadRequest, "protocol.invalid")
		return
	}
	principal, _ := auth.PrincipalFromContext(request.Context())
	credential, err := api.database.ExchangeHostCredential(request.Context(),
		store.UserIdentity{Issuer: principal.Issuer, Subject: principal.Subject}, principal.ProofKeyJKT,
		input.ChallengeID, input.Proof)
	if err != nil {
		api.writeStoreError(response, err)
		return
	}
	writeData(response, http.StatusCreated, credential)
}

func (api *API) health(response http.ResponseWriter, _ *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusNoContent)
}

func (api *API) ready(response http.ResponseWriter, request *http.Request) {
	ctx, cancel := context.WithTimeout(request.Context(), time.Second)
	defer cancel()
	if err := api.database.Ready(ctx); err != nil {
		writeError(response, http.StatusServiceUnavailable, "internal")
		return
	}
	if api.files != nil && !api.files.Ready() {
		writeError(response, http.StatusServiceUnavailable, "file.scanner_unavailable")
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusNoContent)
}

func (api *API) me(response http.ResponseWriter, request *http.Request) {
	principal, _ := auth.PrincipalFromContext(request.Context())
	account, err := api.database.AccountIdentity(request.Context(), store.UserIdentity{Issuer: principal.Issuer, Subject: principal.Subject})
	if err != nil {
		api.writeStoreError(response, err)
		return
	}
	writeData(response, http.StatusOK, map[string]any{
		"issuer": principal.Issuer, "subject": principal.Subject, "client_id": principal.ClientID,
		"scopes": sortedScopes(principal.Scopes), "user_id": account.UserID, "memberships": account.Memberships,
	})
}

func (api *API) currentDevice(response http.ResponseWriter, request *http.Request) {
	principal, _ := auth.PrincipalFromContext(request.Context())
	device, err := api.database.CurrentDevice(request.Context(), store.UserIdentity{Issuer: principal.Issuer, Subject: principal.Subject}, principal.ProofKeyJKT)
	if err != nil {
		api.writeStoreError(response, err)
		return
	}
	writeData(response, http.StatusOK, device)
}

func (api *API) registerDevice(response http.ResponseWriter, request *http.Request) {
	var input deviceRequest
	if !decodeBody(response, request, &input) {
		writeError(response, http.StatusBadRequest, "protocol.invalid")
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" || utf8.RuneCountInString(input.Name) > 160 || strings.IndexFunc(input.Name, unicode.IsControl) >= 0 {
		writeError(response, http.StatusBadRequest, "protocol.invalid")
		return
	}
	approvalThumbprint, err := auth.PublicP256JWKThumbprintJSON(input.ApprovalPublicJWK)
	if err != nil {
		writeError(response, http.StatusBadRequest, "device.key_invalid")
		return
	}
	proofThumbprint, err := auth.PublicP256JWKThumbprintJSON(input.ProofPublicJWK)
	if err != nil {
		writeError(response, http.StatusBadRequest, "device.key_invalid")
		return
	}
	principal, _ := auth.PrincipalFromContext(request.Context())
	if proofThumbprint != principal.ProofKeyJKT {
		writeError(response, http.StatusForbidden, "access.denied")
		return
	}
	if proofThumbprint == approvalThumbprint {
		writeError(response, http.StatusBadRequest, "device.key_invalid")
		return
	}
	if err := api.identity.VerifyDeviceRegistrationProof(input.ApprovalProof, input.ApprovalPublicJWK, principal, input.Name, proofThumbprint); err != nil {
		writeError(response, http.StatusBadRequest, "device.proof_invalid")
		return
	}
	id, err := api.database.RegisterDevice(request.Context(), store.DeviceRegistration{
		Issuer: principal.Issuer, Subject: principal.Subject, Name: input.Name,
		ApprovalPublicJWK: input.ApprovalPublicJWK, ApprovalKeyThumbprint: approvalThumbprint,
		ProofPublicJWK: input.ProofPublicJWK, ProofKeyThumbprint: proofThumbprint,
	})
	if err != nil {
		api.writeStoreError(response, err)
		return
	}
	writeData(response, http.StatusCreated, map[string]any{"device_id": id, "key_version": 1})
}

func (api *API) revokeDevice(response http.ResponseWriter, request *http.Request) {
	id := request.PathValue("id")
	if !uuidPattern.MatchString(id) {
		writeError(response, http.StatusBadRequest, "protocol.invalid")
		return
	}
	principal, _ := auth.PrincipalFromContext(request.Context())
	if err := api.database.RevokeDevice(request.Context(), principal.Issuer, principal.Subject, id); err != nil {
		api.writeStoreError(response, err)
		return
	}
	writeData(response, http.StatusOK, map[string]any{"revoked": true})
}

func (api *API) listHosts(response http.ResponseWriter, request *http.Request) {
	principal, _ := auth.PrincipalFromContext(request.Context())
	items, err := api.database.ListHosts(request.Context(), store.UserIdentity{Issuer: principal.Issuer, Subject: principal.Subject})
	if err != nil {
		api.writeStoreError(response, err)
		return
	}
	writeData(response, http.StatusOK, map[string]any{"items": items})
}

func (api *API) listRuntimes(response http.ResponseWriter, request *http.Request) {
	principal, _ := auth.PrincipalFromContext(request.Context())
	items, err := api.database.ListRuntimes(request.Context(), store.UserIdentity{Issuer: principal.Issuer, Subject: principal.Subject})
	if err != nil {
		api.writeStoreError(response, err)
		return
	}
	writeData(response, http.StatusOK, map[string]any{"items": items})
}

func (api *API) listSessions(response http.ResponseWriter, request *http.Request) {
	runtimeID := request.PathValue("id")
	if !uuidPattern.MatchString(runtimeID) {
		writeError(response, http.StatusBadRequest, "protocol.invalid")
		return
	}
	principal, _ := auth.PrincipalFromContext(request.Context())
	items, err := api.database.ListSessions(request.Context(), store.UserIdentity{Issuer: principal.Issuer, Subject: principal.Subject}, runtimeID)
	if err != nil {
		api.writeStoreError(response, err)
		return
	}
	writeData(response, http.StatusOK, map[string]any{"items": items})
}

func (api *API) commandStatus(response http.ResponseWriter, request *http.Request) {
	requestID := request.PathValue("id")
	deviceID := request.URL.Query().Get("device_id")
	if !uuidPattern.MatchString(requestID) || !uuidPattern.MatchString(deviceID) {
		writeError(response, http.StatusBadRequest, "protocol.invalid")
		return
	}
	principal, _ := auth.PrincipalFromContext(request.Context())
	activeDeviceID, _ := request.Context().Value(deviceContextKey{}).(string)
	if deviceID != activeDeviceID {
		writeError(response, http.StatusForbidden, "access.denied")
		return
	}
	status, err := api.database.CommandStatus(request.Context(), store.UserIdentity{Issuer: principal.Issuer, Subject: principal.Subject}, deviceID, requestID)
	if err != nil {
		api.writeStoreError(response, err)
		return
	}
	writeData(response, http.StatusOK, status)
}

func (api *API) sessionReadAccess(response http.ResponseWriter, request *http.Request) {
	runtimeID, sessionID := request.PathValue("id"), request.PathValue("session_id")
	if !uuidPattern.MatchString(runtimeID) || !uuidPattern.MatchString(sessionID) || request.URL.RawQuery != "" {
		writeError(response, http.StatusBadRequest, "protocol.invalid")
		return
	}
	principal, _ := auth.PrincipalFromContext(request.Context())
	deviceID, _ := request.Context().Value(deviceContextKey{}).(string)
	access, err := api.database.SessionCacheReadAccess(request.Context(), store.UserIdentity{Issuer: principal.Issuer, Subject: principal.Subject},
		deviceID, principal.ProofKeyJKT, runtimeID, sessionID, principal.ExpiresAt)
	if err != nil {
		api.writeStoreError(response, err)
		return
	}
	writeData(response, http.StatusOK, access)
}

func (api *API) sessionTarget(response http.ResponseWriter, request *http.Request) {
	if request.URL.RawQuery != "" {
		writeError(response, http.StatusBadRequest, "protocol.invalid")
		return
	}
	runtime, session := request.PathValue("id"), request.PathValue("session_id")
	if !uuidPattern.MatchString(runtime) || !uuidPattern.MatchString(session) {
		writeError(response, http.StatusBadRequest, "protocol.invalid")
		return
	}
	principal, _ := auth.PrincipalFromContext(request.Context())
	device, _ := request.Context().Value(deviceContextKey{}).(string)
	target, err := api.database.SessionReadTarget(request.Context(), store.UserIdentity{Issuer: principal.Issuer, Subject: principal.Subject}, device, principal.ProofKeyJKT, runtime, session, principal.ExpiresAt)
	if err != nil {
		api.writeStoreError(response, err)
		return
	}
	writeData(response, http.StatusOK, target)
}
func (api *API) questionAnswerStatus(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "protocol.invalid")
		return
	}
	runtime, session, id := r.PathValue("id"), r.PathValue("session_id"), r.PathValue("request_id")
	if !uuidPattern.MatchString(runtime) || !uuidPattern.MatchString(session) || !uuidPattern.MatchString(id) {
		writeError(w, http.StatusBadRequest, "protocol.invalid")
		return
	}
	principal, _ := auth.PrincipalFromContext(r.Context())
	device, _ := r.Context().Value(deviceContextKey{}).(string)
	status, err := api.database.QuestionAnswerStatus(r.Context(), store.UserIdentity{Issuer: principal.Issuer, Subject: principal.Subject}, device, principal.ProofKeyJKT, runtime, session, id, principal.ExpiresAt)
	if err != nil {
		api.writeStoreError(w, err)
		return
	}
	writeData(w, http.StatusOK, status)
}

func (api *API) putRuntimeGrant(response http.ResponseWriter, request *http.Request) {
	runtimeID := request.PathValue("id")
	targetUserID := request.PathValue("user_id")
	if !uuidPattern.MatchString(runtimeID) || !uuidPattern.MatchString(targetUserID) || request.URL.RawQuery != "" {
		writeError(response, http.StatusBadRequest, "protocol.invalid")
		return
	}
	input, ok := decodeRuntimeGrantBody(response, request)
	if !ok {
		writeError(response, http.StatusBadRequest, "grant.invalid")
		return
	}
	input, err := store.NormalizeRuntimeGrantInput(input, time.Now())
	if err != nil {
		writeError(response, http.StatusBadRequest, "grant.invalid")
		return
	}
	principal, _ := auth.PrincipalFromContext(request.Context())
	deviceID, _ := request.Context().Value(deviceContextKey{}).(string)
	version, err := api.database.PutRuntimeGrant(request.Context(), store.UserIdentity{Issuer: principal.Issuer, Subject: principal.Subject}, deviceID, principal.ProofKeyJKT, runtimeID, targetUserID, input)
	if err != nil {
		api.writeStoreError(response, err)
		return
	}
	writeData(response, http.StatusOK, map[string]any{"grant_version": version})
}

func (api *API) revokeRuntimeGrant(response http.ResponseWriter, request *http.Request) {
	runtimeID := request.PathValue("id")
	targetUserID := request.PathValue("user_id")
	if !uuidPattern.MatchString(runtimeID) || !uuidPattern.MatchString(targetUserID) || request.URL.RawQuery != "" || request.ContentLength != 0 || len(request.TransferEncoding) != 0 {
		writeError(response, http.StatusBadRequest, "protocol.invalid")
		return
	}
	principal, _ := auth.PrincipalFromContext(request.Context())
	deviceID, _ := request.Context().Value(deviceContextKey{}).(string)
	version, err := api.database.RevokeRuntimeGrant(request.Context(), store.UserIdentity{Issuer: principal.Issuer, Subject: principal.Subject}, deviceID, principal.ProofKeyJKT, runtimeID, targetUserID)
	if err != nil {
		api.writeStoreError(response, err)
		return
	}
	writeData(response, http.StatusOK, map[string]any{"revoked": true, "grant_version": version})
}

func (api *API) issueRealtimeTicket(response http.ResponseWriter, request *http.Request) {
	var envelope struct {
		RuntimeID string          `json:"runtime_id"`
		Scope     json.RawMessage `json:"scope"`
	}
	if !decodeBody(response, request, &envelope) || !uuidPattern.MatchString(envelope.RuntimeID) {
		writeError(response, http.StatusBadRequest, "protocol.invalid")
		return
	}
	scope, ok := decodeGrantScope(envelope.Scope)
	if !ok {
		writeError(response, http.StatusBadRequest, "grant.invalid")
		return
	}
	principal, _ := auth.PrincipalFromContext(request.Context())
	deviceID, _ := request.Context().Value(deviceContextKey{}).(string)
	ticket, err := api.database.IssueRealtimeTicket(request.Context(),
		store.UserIdentity{Issuer: principal.Issuer, Subject: principal.Subject}, deviceID, envelope.RuntimeID, scope)
	if err != nil {
		api.writeStoreError(response, err)
		return
	}
	writeData(response, http.StatusCreated, ticket)
}

func decodeRuntimeGrantBody(response http.ResponseWriter, request *http.Request) (store.RuntimeGrantInput, bool) {
	var envelope struct {
		Role      string          `json:"role"`
		Scope     json.RawMessage `json:"scope"`
		ExpiresAt *time.Time      `json:"expires_at,omitempty"`
	}
	if !decodeBody(response, request, &envelope) {
		return store.RuntimeGrantInput{}, false
	}
	scope, ok := decodeGrantScope(envelope.Scope)
	if !ok {
		return store.RuntimeGrantInput{}, false
	}
	return store.RuntimeGrantInput{Role: envelope.Role, Scope: scope, ExpiresAt: envelope.ExpiresAt}, true
}

func decodeGrantScope(raw json.RawMessage) (store.GrantScope, bool) {
	if len(raw) == 0 || auth.ValidateJSONObject(raw) != nil {
		return store.GrantScope{}, false
	}
	var scope struct {
		Actions    *[]string `json:"actions"`
		Workspaces *[]string `json:"workspaces"`
		Sessions   *[]string `json:"sessions"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&scope); err != nil || scope.Actions == nil || scope.Workspaces == nil || scope.Sessions == nil {
		return store.GrantScope{}, false
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) {
		return store.GrantScope{}, false
	}
	return store.GrantScope{Actions: *scope.Actions, Workspaces: *scope.Workspaces, Sessions: *scope.Sessions}, true
}

func decodeBody(response http.ResponseWriter, request *http.Request, target any) bool {
	if !strings.EqualFold(strings.TrimSpace(strings.Split(request.Header.Get("Content-Type"), ";")[0]), "application/json") {
		return false
	}
	body, err := io.ReadAll(http.MaxBytesReader(response, request.Body, maxJSONRequestBytes))
	if err != nil || auth.ValidateJSONObject(body) != nil {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return false
	}
	var trailing any
	return errors.Is(decoder.Decode(&trailing), io.EOF)
}

func (api *API) writeStoreError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, files.ErrAccess):
		writeError(response, http.StatusForbidden, "access.denied")
	case errors.Is(err, files.ErrInvalid):
		writeError(response, http.StatusBadRequest, "protocol.invalid")
	case errors.Is(err, files.ErrConflict):
		writeError(response, http.StatusConflict, "file.request_conflict")
	case errors.Is(err, files.ErrQuota):
		writeError(response, http.StatusTooManyRequests, "file.quota_exceeded")
	case errors.Is(err, files.ErrStale):
		writeError(response, http.StatusConflict, "file.state_changed")
	case errors.Is(err, files.ErrScanUnavailable):
		writeError(response, http.StatusServiceUnavailable, "file.scanner_unavailable")
	case errors.Is(err, files.ErrUnavailable), errors.Is(err, files.ErrBlobUnavailable), errors.Is(err, files.ErrEncryption):
		writeError(response, http.StatusServiceUnavailable, "file.unavailable")
	case errors.Is(err, store.ErrIdentityNotProvisioned), errors.Is(err, store.ErrDeviceNotFound):
		writeError(response, http.StatusForbidden, "access.denied")
	case errors.Is(err, store.ErrDeviceRegistrationConflict):
		writeError(response, http.StatusConflict, "device.registration_conflict")
	case errors.Is(err, store.ErrDeviceDirectoryInvalid):
		writeError(response, http.StatusBadRequest, "protocol.invalid")
	case errors.Is(err, store.ErrInstallationManagementInvalid):
		writeError(response, http.StatusBadRequest, "protocol.invalid")
	case errors.Is(err, store.ErrGrantDirectoryInvalid):
		writeError(response, http.StatusBadRequest, "protocol.invalid")
	case errors.Is(err, store.ErrSessionDirectoryInvalid):
		writeError(response, http.StatusBadRequest, "protocol.invalid")
	case errors.Is(err, store.ErrResourceDirectoryInvalid):
		writeError(response, http.StatusBadRequest, "protocol.invalid")
	case errors.Is(err, store.ErrAccessDenied), errors.Is(err, store.ErrGrantNotFound):
		writeError(response, http.StatusForbidden, "access.denied")
	case errors.Is(err, store.ErrTicketInvalid):
		writeError(response, http.StatusUnauthorized, "ticket.invalid")
	case errors.Is(err, store.ErrHostCredentialInvalid):
		writeError(response, http.StatusUnauthorized, "host_credential.invalid")
	case errors.Is(err, store.ErrHostChallengeLimit):
		writeError(response, http.StatusTooManyRequests, "rate.limited")
	case errors.Is(err, store.ErrHostCredentialLimit):
		writeError(response, http.StatusTooManyRequests, "rate.limited")
	case errors.Is(err, store.ErrEnrollmentInvalid):
		writeError(response, http.StatusForbidden, "access.denied")
	case errors.Is(err, store.ErrEnrollmentConflict):
		writeError(response, http.StatusConflict, "enrollment.request_conflict")
	case errors.Is(err, store.ErrEnrollmentLimit):
		writeError(response, http.StatusTooManyRequests, "rate.limited")
	case errors.Is(err, store.ErrGrantInvalid):
		writeError(response, http.StatusBadRequest, "grant.invalid")
	case errors.Is(err, store.ErrApprovalConflict):
		writeError(response, http.StatusConflict, "approval.conflict")
	case errors.Is(err, store.ErrApprovalExpired):
		writeError(response, http.StatusConflict, "approval.expired")
	case errors.Is(err, store.ErrApprovalLimit):
		writeError(response, http.StatusTooManyRequests, "rate.limited")
	case errors.Is(err, auth.ErrAssurance):
		writeError(response, http.StatusForbidden, "approval.assurance_required")
	case errors.Is(err, store.ErrApprovalInvalid):
		writeError(response, http.StatusBadRequest, "protocol.invalid")
	case errors.Is(err, approval.ErrDecision):
		writeError(response, http.StatusBadRequest, "approval.decision_invalid")
	case errors.Is(err, store.ErrDatabaseUnavailable):
		writeError(response, http.StatusServiceUnavailable, "internal")
	default:
		writeError(response, http.StatusInternalServerError, "internal")
	}
}

func writeData(response http.ResponseWriter, status int, data any) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(map[string]any{"ok": true, "data": data})
}

func writeError(response http.ResponseWriter, status int, code string) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(map[string]any{"ok": false, "error": map[string]string{"code": code}})
}

func sortedScopes(scopes map[string]struct{}) []string {
	items := make([]string, 0, len(scopes))
	for scope := range scopes {
		items = append(items, scope)
	}
	sort.Strings(items)
	return items
}
