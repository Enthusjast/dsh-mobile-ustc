package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/httpapi"
	"dsh-mobile-ustc/services/remote/internal/store"
)

func main() {
	if err := run(); err != nil {
		log.Print(err)
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
	database, err := store.Open(context.Background(), os.Getenv("REMOTE_DATABASE_URL"))
	if err != nil {
		return errors.New("remote service database is unavailable or insecurely configured")
	}
	defer database.Close()

	server := &http.Server{
		Addr:              envOr("REMOTE_LISTEN_ADDR", "127.0.0.1:8080"),
		Handler:           httpapi.New(database, verifier, httpapi.Config{HostClientIDs: csv(os.Getenv("REMOTE_HOST_CLIENT_IDS"))}),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
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
