package httpapi_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/control"
	"dsh-mobile-ustc/services/remote/internal/httpapi"
	"dsh-mobile-ustc/services/remote/internal/relay"
	"dsh-mobile-ustc/services/remote/internal/store"
	"dsh-mobile-ustc/services/remote/internal/testsupport"
)

// Two independent production API/relay instances with an isolated mutual-TLS
// node transport. The object/scanner/issuer peers remain explicit fixtures.
func fileOwnerRoutingHandler(t *testing.T, ctx context.Context, postgres *store.Postgres, identity *auth.Authenticator, config httpapi.Config) http.Handler {
	t.Helper()
	ca := testsupport.NewRelayCA(t)
	var handlers [2]*httpapi.Handler
	for index := range handlers {
		node := capacityID()
		_, _, pair := ca.Issue(t, node)
		var api *httpapi.Handler
		private := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { api.PrivateRelayHandler().ServeHTTP(w, r) }))
		private.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: ca.Roots, Certificates: []tls.Certificate{pair}, NextProtos: []string{"http/1.1"}}
		private.StartTLS()
		consumer, err := postgres.NewControlConsumer(ctx, node)
		if err != nil {
			private.Close()
			t.Fatal(err)
		}
		directory, err := consumer.NewRelayDirectory(ctx, private.URL)
		if err != nil {
			private.Close()
			t.Fatal(err)
		}
		api = httpapi.New(directory, identity, config)
		if err := api.ConfigureRouting(relay.RoutingConfig{Directory: directory, ClientTLS: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: ca.Roots, Certificates: []tls.Certificate{pair}}, MaxProxyConnections: 8}); err != nil {
			private.Close()
			t.Fatal(err)
		}
		handlers[index] = api
		worker, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { done <- control.RunConsumer(worker, consumer, api, nil) }()
		t.Cleanup(func() {
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if err := api.Drain(cleanup); err != nil {
				t.Error(err)
			}
			cancel()
			if err := <-done; err != nil {
				t.Error("file relay consumer failed", err)
			}
			if err := consumer.Release(cleanup); err != nil {
				t.Error(err)
			}
			private.Close()
		})
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Header.Get("Authorization"), "DSH-Host ") {
			handlers[0].ServeHTTP(w, r)
			return
		}
		// Phone HTTP, phone WSS and installation file HTTP all enter B, while
		// the live Host is on A. File tickets must be consumed only at A.
		handlers[1].ServeHTTP(w, r)
	})
}
