package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/store"
)

type fakeRepository struct {
	readyError              error
	account                 store.AccountIdentity
	accountErr              error
	accountCalls            int
	accountLookup           store.UserIdentity
	currentDevice           store.CurrentDevice
	currentDeviceErr        error
	currentDeviceCalls      int
	currentDeviceIdentity   store.UserIdentity
	currentDeviceJKT        string
	listCalls               int
	activeDeviceID          string
	activeDeviceErr         error
	activeDeviceCall        int
	commandCalls            int
	cacheAccess             store.SessionReadAccess
	cacheAccessErr          error
	cacheAccessCalls        int
	cacheIdentity           store.UserIdentity
	cacheDevice             string
	cacheJKT                string
	cacheRuntime            string
	cacheSession            string
	cacheCredentialUntil    time.Time
	ticketCalls             int
	enrollmentCalls         int
	enrollmentResult        store.EnrollmentCreated
	enrollmentInfo          store.EnrollmentInfo
	enrollmentReadCalls     int
	enrollmentPreviewCalls  int
	enrollmentPreviewActor  store.UserIdentity
	enrollmentPreviewCode   string
	hostConfirmCalls        int
	hostConfirmJKT          string
	challengeCalls          int
	challengeJKT            string
	challengeResult         store.HostCredentialChallenge
	credentialCalls         int
	credentialJKT           string
	credentialID            string
	credentialProof         string
	credentialResult        store.HostConnectionCredential
	relayTicket             store.TicketRedemption
	relayTicketPrepareCalls int
	relayTicketConsumeCalls int
	relayTicketErr          error
	hostCredential          store.HostCredentialIdentity
	hostCredentialErr       error
	runtimeConnection       store.RuntimeConnection
	runtimeConnectErr       error
	runtimeTouchErr         error
}

func (fake *fakeRepository) Ready(context.Context) error { return fake.readyError }
func (fake *fakeRepository) AccountIdentity(_ context.Context, identity store.UserIdentity) (store.AccountIdentity, error) {
	fake.accountCalls++
	fake.accountLookup = identity
	return fake.account, fake.accountErr
}
func (fake *fakeRepository) CurrentDevice(_ context.Context, identity store.UserIdentity, jkt string) (store.CurrentDevice, error) {
	fake.currentDeviceCalls++
	fake.currentDeviceIdentity = identity
	fake.currentDeviceJKT = jkt
	return fake.currentDevice, fake.currentDeviceErr
}
func (fake *fakeRepository) ActiveDevice(context.Context, store.UserIdentity, string) (string, error) {
	fake.activeDeviceCall++
	return fake.activeDeviceID, fake.activeDeviceErr
}
func (fake *fakeRepository) CreateEnrollment(context.Context, store.EnrollmentInput) (store.EnrollmentCreated, error) {
	fake.enrollmentCalls++
	return fake.enrollmentResult, nil
}
func (fake *fakeRepository) GetEnrollment(context.Context, store.UserIdentity, string) (store.EnrollmentInfo, error) {
	fake.enrollmentReadCalls++
	if fake.enrollmentInfo.EnrollmentID == "" {
		return store.EnrollmentInfo{}, errors.New("not implemented")
	}
	return fake.enrollmentInfo, nil
}
func (fake *fakeRepository) PreviewEnrollment(_ context.Context, actor store.UserIdentity, _, code string) (store.EnrollmentInfo, error) {
	fake.enrollmentPreviewCalls++
	fake.enrollmentPreviewActor = actor
	fake.enrollmentPreviewCode = code
	if fake.enrollmentInfo.EnrollmentID == "" {
		return store.EnrollmentInfo{}, errors.New("not implemented")
	}
	return fake.enrollmentInfo, nil
}
func (fake *fakeRepository) ConfirmEnrollmentUser(context.Context, store.UserIdentity, string, string, string) (store.EnrollmentConfirmation, error) {
	return store.EnrollmentConfirmation{}, errors.New("not implemented")
}
func (fake *fakeRepository) ConfirmEnrollmentHost(_ context.Context, _ store.UserIdentity, thumbprint, enrollmentID, _ string) (store.EnrollmentConfirmation, error) {
	fake.hostConfirmCalls++
	fake.hostConfirmJKT = thumbprint
	return store.EnrollmentConfirmation{EnrollmentID: enrollmentID, State: "approved"}, nil
}
func (fake *fakeRepository) CreateHostCredentialChallenge(_ context.Context, _ store.UserIdentity, thumbprint string) (store.HostCredentialChallenge, error) {
	fake.challengeCalls++
	fake.challengeJKT = thumbprint
	return fake.challengeResult, nil
}
func (fake *fakeRepository) ExchangeHostCredential(_ context.Context, _ store.UserIdentity, thumbprint, challengeID, proof string) (store.HostConnectionCredential, error) {
	fake.credentialCalls++
	fake.credentialJKT = thumbprint
	fake.credentialID = challengeID
	fake.credentialProof = proof
	return fake.credentialResult, nil
}
func (fake *fakeRepository) RegisterDevice(context.Context, store.DeviceRegistration) (string, error) {
	return "", errors.New("not implemented")
}
func (fake *fakeRepository) RevokeDevice(context.Context, string, string, string) error {
	return errors.New("not implemented")
}
func (fake *fakeRepository) PutRuntimeGrant(context.Context, store.UserIdentity, string, string, string, store.RuntimeGrantInput) (int64, error) {
	return 1, nil
}
func (fake *fakeRepository) RevokeRuntimeGrant(context.Context, store.UserIdentity, string, string, string) (int64, error) {
	return 2, nil
}
func (fake *fakeRepository) IssueRealtimeTicket(context.Context, store.UserIdentity, string, string, store.GrantScope) (store.RealtimeTicket, error) {
	fake.ticketCalls++
	return store.RealtimeTicket{Token: strings.Repeat("A", 43), ExpiresAt: time.Now().Add(30 * time.Second)}, nil
}
func (fake *fakeRepository) PrepareRealtimeTicket(context.Context, string) (store.TicketRedemption, error) {
	fake.relayTicketPrepareCalls++
	return fake.relayTicket, fake.relayTicketErr
}
func (fake *fakeRepository) ConsumeRealtimeTicket(context.Context, string) (store.TicketRedemption, error) {
	fake.relayTicketConsumeCalls++
	return fake.relayTicket, fake.relayTicketErr
}
func (fake *fakeRepository) ValidateRealtimeLease(context.Context, store.TicketRedemption) error {
	return nil
}
func (fake *fakeRepository) AuthorizeRealtimeCommandReceipt(context.Context, store.TicketRedemption, store.CommandStatus) error {
	return nil
}
func (fake *fakeRepository) LookupHostConnectionCredential(context.Context, string) (store.HostCredentialIdentity, error) {
	return fake.hostCredential, fake.hostCredentialErr
}
func (fake *fakeRepository) AttachRuntimeConnection(context.Context, store.RuntimeConnectionInput) (store.RuntimeConnection, error) {
	return fake.runtimeConnection, fake.runtimeConnectErr
}
func (fake *fakeRepository) TouchRuntimeConnection(context.Context, string, string, string, string) error {
	return fake.runtimeTouchErr
}
func (fake *fakeRepository) SyncRealtimeSessionCatalog(context.Context, store.RuntimeConnection, int64, bool, []store.SessionCatalogItem) error {
	return nil
}

func (fake *fakeRepository) AuthorizeRealtimeSessionRead(context.Context, store.TicketRedemption, string) error {
	return nil
}
func (fake *fakeRepository) AuthorizeRealtimeQuestion(context.Context, store.TicketRedemption, string) error {
	return nil
}

func (fake *fakeRepository) InvalidRealtimeConnectionLeases(context.Context, []store.RealtimeConnectionLease) ([]string, error) {
	return nil, nil
}

func (fake *fakeRepository) DetachRuntimeConnection(context.Context, string, string, string, string) error {
	return nil
}
func (fake *fakeRepository) RecordRealtimeCommand(context.Context, store.TicketRedemption, string, string, string, string) (store.CommandStatus, error) {
	return store.CommandStatus{}, nil
}
func (fake *fakeRepository) RecordRealtimeSessionCreate(context.Context, store.TicketRedemption, string, string, string) (store.CommandStatus, error) {
	return store.CommandStatus{}, nil
}
func (fake *fakeRepository) RecordRealtimeCommandReceipt(context.Context, store.RelayCommandReceipt) (store.CommandStatus, error) {
	return store.CommandStatus{}, nil
}
func (fake *fakeRepository) MarkRealtimeCommandUnknown(context.Context, store.TicketRedemption, string, string, string) (store.CommandStatus, error) {
	return store.CommandStatus{}, nil
}
func (fake *fakeRepository) ListHosts(context.Context, store.UserIdentity) ([]store.Host, error) {
	fake.listCalls++
	return []store.Host{}, nil
}
func (fake *fakeRepository) ListRuntimes(context.Context, store.UserIdentity) ([]store.Runtime, error) {
	return []store.Runtime{}, nil
}
func (fake *fakeRepository) ListSessions(context.Context, store.UserIdentity, string) ([]store.Session, error) {
	return []store.Session{}, nil
}
func (fake *fakeRepository) SessionCacheReadAccess(_ context.Context, identity store.UserIdentity, device, jkt, runtime, session string, until time.Time) (store.SessionReadAccess, error) {
	fake.cacheAccessCalls++
	fake.cacheIdentity = identity
	fake.cacheDevice = device
	fake.cacheJKT = jkt
	fake.cacheRuntime = runtime
	fake.cacheSession = session
	fake.cacheCredentialUntil = until
	if fake.cacheAccess.RuntimeID == "" && fake.cacheAccessErr == nil {
		return store.SessionReadAccess{}, store.ErrAccessDenied
	}
	return fake.cacheAccess, fake.cacheAccessErr
}
func (fake *fakeRepository) CommandStatus(context.Context, store.UserIdentity, string, string) (store.CommandStatus, error) {
	fake.commandCalls++
	return store.CommandStatus{}, errors.New("not implemented")
}

func TestHealthAndReadinessRoutes(t *testing.T) {
	repo := &fakeRepository{}
	handler := New(repo, nil)

	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if health.Code != http.StatusNoContent {
		t.Fatalf("health status = %d, want 204", health.Code)
	}
	if repo.listCalls != 0 {
		t.Fatal("health endpoint accessed user data")
	}

	repo.readyError = store.ErrDatabaseUnavailable
	notReady := httptest.NewRecorder()
	handler.ServeHTTP(notReady, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if notReady.Code != http.StatusServiceUnavailable {
		t.Fatalf("unready status = %d, want 503", notReady.Code)
	}

	repo.readyError = nil
	ready := httptest.NewRecorder()
	handler.ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusNoContent {
		t.Fatalf("ready status = %d, want 204", ready.Code)
	}
}

func TestProtectedRoutesRejectAnonymousRequestsBeforeDatabaseAccess(t *testing.T) {
	identity, err := auth.New(auth.Config{
		Issuer: "https://id.example.edu", Audience: "urn:dsh-remote", JWKSURL: "https://keys.example.edu/jwks",
		AllowedClients: []string{"mobile-client"}, RequiredScopes: []string{"remote.access"},
		PublicOrigin: "https://api.example.edu", MaxTokenLifetime: 15 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	repo := &fakeRepository{}
	handler := New(repo, identity)
	for _, target := range []string{"/v1/me", "/v1/devices/current", "/v1/hosts", "/v1/runtimes", "/v1/runtimes/44444444-4444-4444-8444-444444444444/sessions", "/v1/runtimes/44444444-4444-4444-8444-444444444444/sessions/55555555-5555-4555-8555-555555555555/read-access"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, target, nil))
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("anonymous GET %s status = %d, want 401", target, response.Code)
		}
	}
	if repo.listCalls != 0 || repo.accountCalls != 0 || repo.currentDeviceCalls != 0 || repo.cacheAccessCalls != 0 {
		t.Fatal("unauthenticated route accessed the repository")
	}
}

func TestDeviceDecoderRejectsUnknownDuplicateAndOversizedJSON(t *testing.T) {
	decode := func(body string, contentType string) bool {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/v1/devices", strings.NewReader(body))
		request.Header.Set("Content-Type", contentType)
		var target deviceRequest
		return decodeBody(response, request, &target)
	}
	valid := `{"name":"phone","approval_public_jwk":{},"approval_proof":"proof","proof_public_jwk":{}}`
	if !decode(valid, "application/json") {
		t.Fatal("valid device JSON was rejected")
	}
	for _, input := range []struct{ body, contentType string }{
		{body: `{"name":"phone","name":"other","approval_public_jwk":{},"proof_public_jwk":{}}`, contentType: "application/json"},
		{body: `{"name":"phone","approval_public_jwk":{},"proof_public_jwk":{},"access_token":"secret"}`, contentType: "application/json"},
		{body: `{`, contentType: "application/json"},
		{body: valid, contentType: "text/plain"},
		{body: strings.Repeat("x", maxJSONRequestBytes+1), contentType: "application/json"},
	} {
		if decode(input.body, input.contentType) {
			t.Fatal("invalid device request was accepted")
		}
	}
}

func TestGrantDecoderRequiresExplicitScopeArraysAndRejectsUnknownMembers(t *testing.T) {
	decode := func(body string) bool {
		request := httptest.NewRequest(http.MethodPut, "/v1/runtimes/44444444-4444-4444-8444-444444444444/grants/55555555-5555-4555-8555-555555555555", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		_, ok := decodeRuntimeGrantBody(response, request)
		return ok
	}
	if !decode(`{"role":"viewer","scope":{"actions":["host.list"],"workspaces":[],"sessions":[]}}`) {
		t.Fatal("valid grant request rejected")
	}
	for _, body := range []string{
		`{"role":"viewer","scope":{"actions":["host.list"],"sessions":[]}}`,
		`{"role":"viewer","scope":{"actions":["host.list"],"workspaces":null,"sessions":[]}}`,
		`{"role":"viewer","scope":{"actions":["host.list"],"workspaces":[],"sessions":[],"all":true}}`,
		`{"role":"viewer","scope":{"actions":["host.list"],"workspaces":[],"sessions":[]},"unknown":true}`,
		`{"role":"viewer","role":"owner","scope":{"actions":[],"workspaces":[],"sessions":[]}}`,
	} {
		if decode(body) {
			t.Fatalf("invalid grant request accepted: %s", body)
		}
	}
}
