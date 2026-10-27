package main

import (
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/observability"
)

func TestMetricsListenerIsExplicitAndRejectsPublicOrAmbiguousBindings(t *testing.T) {
	if endpoint, err := startMetricsEndpoint("", nil); endpoint != nil || err != nil {
		t.Fatal("default configuration opened metrics")
	}
	m := observability.New()
	for _, address := range []string{":9090", "0.0.0.0:9090", "[::]:9090", "192.0.2.4:9090", "localhost:9090", "127.0.0.1", "http://127.0.0.1:9090", "127.0.0.1:-1", "127.0.0.1:65536", "127.0.0.1:bad"} {
		if endpoint, err := startMetricsEndpoint(address, m); err == nil || endpoint != nil {
			if endpoint != nil {
				endpoint.close()
			}
			t.Fatalf("accepted metrics binding %q", address)
		}
	}
}

func TestMetricsListenerHasOnlyItsOwnRouteAndClosesItsPort(t *testing.T) {
	endpoint, err := startMetricsEndpoint("127.0.0.1:0", observability.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(endpoint.close)
	address := endpoint.listener.Addr().String()
	client := &http.Client{Timeout: time.Second}
	t.Cleanup(client.CloseIdleConnections)
	for _, check := range []struct {
		method, path string
		status       int
	}{
		{"GET", "/metrics", 200}, {"GET", "/readyz", 404}, {"GET", "/v1/me", 404}, {"POST", "/metrics", 405},
	} {
		request, _ := http.NewRequest(check.method, "http://"+address+check.path, nil)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if readErr != nil || response.StatusCode != check.status {
			t.Fatalf("route %s %s: status=%d err=%v", check.method, check.path, response.StatusCode, readErr)
		}
		if check.status == 200 && (!strings.Contains(string(body), "dsh_remote_control_available") || response.Header.Get("Cache-Control") != "no-store") {
			t.Fatal("missing private-registry metrics")
		}
	}
	// An unexpected listener failure must be observable by the main lifecycle.
	_ = endpoint.listener.Close()
	select {
	case err := <-endpoint.errors():
		if err == nil {
			t.Fatal("listener failure disappeared")
		}
	case <-time.After(time.Second):
		t.Fatal("listener failure was not reported")
	}
	endpoint.close()
	rebound, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal("metrics port leaked after close", err)
	}
	_ = rebound.Close()
}
