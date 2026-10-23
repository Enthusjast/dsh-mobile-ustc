package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"dsh-mobile-ustc/services/remote/internal/auth"
)

func main() {
	if err := run(); err != nil {
		log.Print("remote service stopped")
		os.Exit(1)
	}
}

func run() error {
	verifier, err := auth.New(auth.Config{
		Issuer:           os.Getenv("REMOTE_ISSUER"),
		Audience:         os.Getenv("REMOTE_AUDIENCE"),
		JWKSURL:          os.Getenv("REMOTE_JWKS_URL"),
		AllowedClients:   csv(os.Getenv("REMOTE_CLIENT_IDS")),
		RequiredScopes:   csv(os.Getenv("REMOTE_REQUIRED_SCOPES")),
		PublicOrigin:     os.Getenv("REMOTE_PUBLIC_ORIGIN"),
		MaxTokenLifetime: 15 * time.Minute,
	})
	if err != nil {
		return fmt.Errorf("remote service identity configuration is invalid: %w", err)
	}

	api := http.NewServeMux()
	api.HandleFunc("GET /healthz", func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Cache-Control", "no-store")
		response.WriteHeader(http.StatusNoContent)
	})
	api.Handle("GET /v1/me", verifier.Middleware(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		principal, ok := auth.PrincipalFromContext(request.Context())
		if !ok {
			writeError(response, http.StatusUnauthorized, "auth.expired")
			return
		}
		scopes := make([]string, 0, len(principal.Scopes))
		for scope := range principal.Scopes {
			scopes = append(scopes, scope)
		}
		sort.Strings(scopes)
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{"ok": true, "data": map[string]any{
			"issuer":    principal.Issuer,
			"subject":   principal.Subject,
			"client_id": principal.ClientID,
			"scopes":    scopes,
		}})
	})))

	server := &http.Server{
		Addr:              envOr("REMOTE_LISTEN_ADDR", "127.0.0.1:8080"),
		Handler:           api,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	result := make(chan error, 1)
	go func() { result <- server.ListenAndServe() }()
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			return fmt.Errorf("remote service shutdown failed: %w", err)
		}
		err := <-result
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("remote service failed before shutdown: %w", err)
		}
		return nil
	case err := <-result:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("remote service listener failed: %w", err)
	}
}

func csv(value string) []string {
	parts := strings.Split(value, ",")
	items := make([]string, 0, len(parts))
	for _, part := range parts {
		if item := strings.TrimSpace(part); item != "" {
			items = append(items, item)
		}
	}
	return items
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func writeError(response http.ResponseWriter, status int, code string) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(map[string]any{"ok": false, "error": map[string]string{"code": code}})
}
