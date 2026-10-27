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
	"dsh-mobile-ustc/services/remote/internal/relay"
	"dsh-mobile-ustc/services/remote/internal/store"
)

func main() {
	operation := run
	if len(os.Args) > 1 {
		if os.Args[1] == "recovery" {
			operation = func() error { return runRecoveryCommand(os.Args[2:], os.Stdout) }
		} else {
			operation = func() error { return errors.New("remote service arguments are invalid") }
		}
	}
	if err := operation(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run() error {
	nodeID := strings.TrimSpace(os.Getenv("REMOTE_RELAY_NODE_ID"))
	relayConfig, err := loadRelayDeployment(os.Getenv("REMOTE_RELAY_CONFIG_FILE"), nodeID)
	if err != nil {
		return err
	}
	scope, err := auth.ProofScope(os.Getenv("REMOTE_ISSUER"), os.Getenv("REMOTE_AUDIENCE"), os.Getenv("REMOTE_PUBLIC_ORIGIN"))
	if err != nil {
		return fmt.Errorf("remote service identity configuration is invalid: %w", err)
	}
	database, err := store.Open(context.Background(), os.Getenv("REMOTE_DATABASE_URL"))
	if err != nil {
		return errors.New("remote service database is unavailable or insecurely configured")
	}
	defer database.Close()
	recovery, err := database.NewRecoveryGuard(context.Background(), os.Getenv("REMOTE_DATABASE_EPOCH"))
	if err != nil {
		return errors.New("remote service database recovery is unavailable or deployment epoch does not match")
	}
	scope, err = auth.ProofScopeInEpoch(scope, recovery.Epoch())
	if err != nil {
		return errors.New("remote service proof epoch is invalid")
	}
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
		DatabaseEpoch:    recovery.Epoch(),
		MinimumIssuedAt:  recovery.TokenNotBefore(),
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
	consumer, err := database.NewControlConsumer(context.Background(), nodeID)
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
	origin := ""
	if relayConfig != nil {
		origin = relayConfig.Origin
	}
	directory, err := consumer.NewRelayDirectory(context.Background(), origin)
	if err != nil {
		return errors.New("remote relay directory is unavailable")
	}
	handler := httpapi.New(directory, verifier, apiConfig)
	routingConfig := relay.RoutingConfig{Directory: directory}
	if relayConfig != nil {
		routingConfig.ClientTLS, routingConfig.MaxProxyConnections = relayConfig.clientTLS, relayConfig.MaxProxyConnections
	}
	if err := handler.ConfigureRouting(routingConfig); err != nil {
		return errRelayConfiguration
	}
	privateEndpoint, err := startRelayEndpoint(relayConfig, recovery.Middleware(handler.PrivateRelayHandler()))
	if err != nil {
		return err
	}
	defer privateEndpoint.close()
	// Also fence upgraded transports if any listener exits unexpectedly.
	defer func() {
		drain, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = handler.Drain(drain)
	}()
	metricsEndpoint, err := startMetricsEndpoint(metricsAddress, metrics)
	if err != nil {
		return err
	}
	defer metricsEndpoint.close()
	server := &http.Server{
		Addr:              envOr("REMOTE_LISTEN_ADDR", "127.0.0.1:8080"),
		Handler:           recovery.Middleware(handler),
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
	recoveryDone := make(chan struct{})
	recoveryFailure := make(chan error, 1)
	go func() {
		defer close(recoveryDone)
		if err := recovery.Run(controlCtx); err != nil {
			recoveryFailure <- err
		}
	}()
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
	defer func() {
		stopControl()
		<-controlDone
		<-filesDone
		<-pushDone
		<-proofsDone
		<-recoveryDone
	}()
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
			drained <- handler.Drain(shutdown)
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
	case <-privateEndpoint.errors():
		_ = server.Close()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := handler.Drain(shutdown); err != nil {
			return fmt.Errorf("remote private relay failed and realtime drain failed: %w", err)
		}
		return errors.New("remote private relay listener failed")
	case <-recoveryFailure:
		_ = server.Close()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := handler.Drain(shutdown); err != nil {
			return fmt.Errorf("remote recovery fence failed and realtime drain failed: %w", err)
		}
		return errors.New("remote service database recovery authority unavailable")
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
