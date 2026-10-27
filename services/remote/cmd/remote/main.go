package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/control"
	"dsh-mobile-ustc/services/remote/internal/httpapi"
	"dsh-mobile-ustc/services/remote/internal/observability"
	"dsh-mobile-ustc/services/remote/internal/store"
)

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run() error {
	scope, err := auth.ProofScope(os.Getenv("REMOTE_ISSUER"), os.Getenv("REMOTE_AUDIENCE"), os.Getenv("REMOTE_PUBLIC_ORIGIN"))
	if err != nil {
		return fmt.Errorf("remote service identity configuration is invalid: %w", err)
	}
	database, err := store.Open(context.Background(), os.Getenv("REMOTE_DATABASE_URL"))
	if err != nil {
		return errors.New("remote service database is unavailable or insecurely configured")
	}
	defer database.Close()
	proofLimit := store.DefaultProofEntriesPerBucket
	if configured := strings.TrimSpace(os.Getenv("REMOTE_DPOP_ENTRIES_PER_BUCKET")); configured != "" {
		parsed, err := strconv.Atoi(configured)
		if err != nil {
			return errors.New("remote proof-state capacity is invalid")
		}
		proofLimit = parsed
	}
	proofs, err := store.NewPostgresProofStore(context.Background(), database.DB, scope, proofLimit)
	if err != nil {
		return errors.New("remote shared proof state is unavailable or inconsistently configured")
	}
	verifier, err := auth.New(auth.Config{
		Issuer:           os.Getenv("REMOTE_ISSUER"),
		Audience:         os.Getenv("REMOTE_AUDIENCE"),
		JWKSURL:          os.Getenv("REMOTE_JWKS_URL"),
		AllowedClients:   csv(os.Getenv("REMOTE_CLIENT_IDS")),
		RequiredScopes:   csv(os.Getenv("REMOTE_REQUIRED_SCOPES")),
		PublicOrigin:     os.Getenv("REMOTE_PUBLIC_ORIGIN"),
		MaxTokenLifetime: 15 * time.Minute,
		Proofs:           proofs,
	})
	if err != nil {
		return fmt.Errorf("remote service identity configuration is invalid: %w", err)
	}
	admissions := store.DefaultSerializableAdmissions
	if configured := strings.TrimSpace(os.Getenv("REMOTE_SERIALIZABLE_ADMISSIONS")); configured != "" {
		parsed, parseErr := strconv.Atoi(configured)
		if parseErr != nil {
			return errors.New("remote serializable admission budget is invalid")
		}
		admissions = parsed
	}
	if err := database.ConfigureSerializableAdmissions(admissions); err != nil {
		return errors.New("remote serializable admission budget must be between 1 and 30")
	}
	approvalConfig, err := loadApprovalConfig(os.Getenv("REMOTE_APPROVAL_POLICY_FILE"), database, os.Getenv("REMOTE_ISSUER"), csv(os.Getenv("REMOTE_CLIENT_IDS")))
	if err != nil {
		return err
	}
	fileRuntime, err := loadFileRuntime(os.Getenv("REMOTE_FILES_CONFIG_FILE"), database)
	if err != nil {
		return err
	}
	defer fileRuntime.Close()
	pushRuntime, err := loadPushRuntime(os.Getenv("REMOTE_PUSH_CONFIG_FILE"), database, os.Getenv("REMOTE_ISSUER"), approvalConfig)
	if err != nil {
		return err
	}

	metricsAddress := strings.TrimSpace(os.Getenv("REMOTE_METRICS_LISTEN_ADDR"))
	var metrics *observability.Metrics
	if metricsAddress != "" {
		metrics = observability.New()
	}
	apiConfig := httpapi.Config{HostClientIDs: csv(os.Getenv("REMOTE_HOST_CLIENT_IDS")), Approvals: approvalConfig, Metrics: metrics}
	if fileRuntime != nil {
		apiConfig.Files = fileRuntime.service
		apiConfig.FileHandoffs = fileRuntime.handoffs
		apiConfig.FileExports = fileRuntime.exports
	}
	if pushRuntime != nil {
		apiConfig.Push = pushRuntime.repository
	}
	apiConfig.Releases, err = loadAppReleases(os.Getenv("REMOTE_APP_RELEASES_FILE"))
	if err != nil {
		return err
	}
	handler := httpapi.New(database, verifier, apiConfig)
	consumer, err := database.NewControlConsumer(context.Background(), strings.TrimSpace(os.Getenv("REMOTE_RELAY_NODE_ID")))
	if err != nil {
		return errors.New("remote control consumer is unavailable or already active")
	}
	defer func() {
		release, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := consumer.Release(release); err != nil {
			log.Print("remote control consumer release unavailable=true")
		}
	}()
	metricsEndpoint, err := startMetricsEndpoint(metricsAddress, metrics)
	if err != nil {
		return err
	}
	defer metricsEndpoint.close()
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
	controlFailure := make(chan error, 1)
	proofsDone := make(chan struct{})
	go func() { defer close(proofsDone); proofs.Run(controlCtx) }()
	go func() {
		defer close(controlDone)
		if err := control.RunConsumer(controlCtx, consumer, handler, metrics); err != nil {
			controlFailure <- err
		}
	}()
	filesDone := make(chan struct{})
	if fileRuntime != nil {
		go func() { defer close(filesDone); fileRuntime.service.Run(controlCtx) }()
	} else {
		close(filesDone)
	}
	pushDone := make(chan struct{})
	if pushRuntime != nil {
		go func() { defer close(pushDone); pushRuntime.Run(controlCtx) }()
	} else {
		close(pushDone)
	}
	defer func() { stopControl(); <-controlDone; <-filesDone; <-pushDone; <-proofsDone }()
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
	case <-metricsEndpoint.errors():
		// An explicitly configured listener is part of the service lifecycle.
		// Stop admission and drain upgraded peers before returning a failure.
		_ = server.Close()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := handler.Drain(shutdown); err != nil {
			return fmt.Errorf("remote metrics failed and realtime drain failed: %w", err)
		}
		return errors.New("remote metrics listener failed")
	case <-controlFailure:
		_ = server.Close()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := handler.Drain(shutdown); err != nil {
			return fmt.Errorf("remote control consumer failed and realtime drain failed: %w", err)
		}
		return errors.New("remote control consumer authority unavailable")
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
