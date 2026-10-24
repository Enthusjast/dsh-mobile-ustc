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
	"dsh-mobile-ustc/services/remote/internal/control"
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
	approvalConfig, err := loadApprovalConfig(os.Getenv("REMOTE_APPROVAL_POLICY_FILE"), database, os.Getenv("REMOTE_ISSUER"), csv(os.Getenv("REMOTE_CLIENT_IDS")))
	if err != nil {
		return err
	}

	handler := httpapi.New(database, verifier, httpapi.Config{HostClientIDs: csv(os.Getenv("REMOTE_HOST_CLIENT_IDS")), Approvals: approvalConfig})
	server := &http.Server{
		Addr:              envOr("REMOTE_LISTEN_ADDR", "127.0.0.1:8080"),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	controlCtx, stopControl := context.WithCancel(ctx)
	controlDone := make(chan struct{})
	go func() { defer close(controlDone); control.Run(controlCtx, database, handler) }()
	defer func() { stopControl(); <-controlDone }()
	result := make(chan error, 1)
	go func() { result <- server.ListenAndServe() }()
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// Closing upgraded peers also cancels pending approval detail RPCs. Run
		// this alongside HTTP shutdown so an active admission cannot hold shutdown
		// open while waiting for a host that has not yet been drained.
		drained := make(chan error, 1)
		go func() {
			var drainErr error
			if drainer, ok := server.Handler.(interface{ Drain(context.Context) error }); ok {
				drainErr = drainer.Drain(shutdown)
			}
			drained <- drainErr
		}()
		shutdownErr := server.Shutdown(shutdown)
		drainErr := <-drained
		if shutdownErr != nil {
			_ = server.Close()
			return fmt.Errorf("remote service shutdown failed: %w", shutdownErr)
		}
		if drainErr != nil {
			_ = server.Close()
			return fmt.Errorf("remote realtime drain failed: %w", drainErr)
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
