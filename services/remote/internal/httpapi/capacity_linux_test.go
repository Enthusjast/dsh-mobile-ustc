package httpapi_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/store"
	"dsh-mobile-ustc/services/remote/internal/testsupport"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

type capacityConfig struct {
	Race            bool `json:"race"`
	Connections     int  `json:"connections"`
	Workers         int  `json:"workers"`
	HoldSeconds     int  `json:"hold_seconds"`
	ActivePairs     int  `json:"active_pairs"`
	EventsPerSecond int  `json:"events_per_second"`
	PayloadBytes    int  `json:"payload_bytes"`
}

func (config capacityConfig) validate() error {
	if config.Connections < 4 || config.Connections > 12000 || config.Connections%2 != 0 || config.Workers < 1 || config.Workers > 64 ||
		config.HoldSeconds < 5 || config.HoldSeconds > 90 || config.ActivePairs < 0 || config.ActivePairs > min(2000, config.Connections/2) ||
		config.EventsPerSecond < 1 || config.EventsPerSecond > 20 || config.PayloadBytes < 128 || config.PayloadBytes > 16384 {
		return errors.New("capacity configuration outside explicit fixture bounds")
	}
	return nil
}

func capacityParallel(ctx context.Context, count, workers int, run func(context.Context, int) error) error {
	work, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan int)
	var group sync.WaitGroup
	var once sync.Once
	var first error
	for range min(count, workers) {
		group.Add(1)
		go func() {
			defer group.Done()
			for index := range jobs {
				if work.Err() != nil {
					return
				}
				if err := run(work, index); err != nil {
					once.Do(func() { first = err; cancel() })
					return
				}
			}
		}()
	}
	for index := 0; index < count; index++ {
		select {
		case jobs <- index:
		case <-work.Done():
			index = count
		}
	}
	close(jobs)
	group.Wait()
	if first != nil {
		return first
	}
	return ctx.Err()
}

func capacityQuantiles(values []time.Duration) map[string]float64 {
	var positive []time.Duration
	for _, value := range values {
		if value > 0 {
			positive = append(positive, value)
		}
	}
	values = positive
	if len(values) == 0 {
		return map[string]float64{}
	}
	values = append([]time.Duration(nil), values...)
	slices.Sort(values)
	result := map[string]float64{}
	for name, fraction := range map[string]float64{"p50": .5, "p95": .95, "p99": .99, "max": 1} {
		index := min(len(values)-1, int(math.Ceil(float64(len(values))*fraction))-1)
		result[name] = float64(values[index]) / float64(time.Millisecond)
	}
	return result
}

func capacityOwnResources() map[string]float64 {
	var usage syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &usage)
	result := map[string]float64{"cpu_seconds": float64(usage.Utime.Sec+usage.Stime.Sec) + float64(usage.Utime.Usec+usage.Stime.Usec)/1e6}
	if fields, err := os.ReadFile("/proc/self/statm"); err == nil {
		parts := strings.Fields(string(fields))
		if len(parts) > 1 {
			pages, _ := strconv.ParseFloat(parts[1], 64)
			result["rss_bytes"] = pages * float64(os.Getpagesize())
		}
	}
	if entries, err := os.ReadDir("/proc/self/fd"); err == nil {
		result["fds"] = float64(len(entries))
	}
	result["goroutines"] = float64(runtime.NumGoroutine())
	return result
}

func capacityDatabaseDSN(ctx context.Context, db *sql.DB) (string, error) {
	config, err := pgx.ParseConfig(os.Getenv("REMOTE_TEST_DATABASE_URL"))
	if err != nil {
		return "", err
	}
	if err := db.QueryRowContext(ctx, "select current_database()").Scan(&config.Database); err != nil {
		return "", err
	}
	quote := func(value string) string {
		return "'" + strings.ReplaceAll(strings.ReplaceAll(value, "\\", "\\\\"), "'", "\\'") + "'"
	}
	return "host=" + quote(config.Host) + " port=" + strconv.Itoa(int(config.Port)) + " user=" + quote(config.User) + " password=" + quote(config.Password) + " dbname=" + quote(config.Database) + " sslmode=disable", nil
}

func capacitySeed(ctx context.Context, db *sql.DB, count int, issuer string) ([]*capacityPair, error) {
	transaction, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, errors.New("seed transaction failed")
	}
	defer transaction.Rollback()
	org := capacityID()
	if _, err = transaction.ExecContext(ctx, `insert into orgs(id,slug,name) values($1,'capacity','Capacity fixture')`, org); err != nil {
		return nil, errors.New("seed organization failed")
	}
	pairs := make([]*capacityPair, count)
	for index := range pairs {
		pair := &capacityPair{user: capacityID(), host: capacityID(), installation: capacityID(), runtime: capacityID(), epoch: capacityID(), workspace: capacityID(), device: capacityID()}
		pair.session, _ = store.MobileSessionID(pair.runtime, "capacity-session")
		pair.hostKey, err = newCapacityKey()
		if err != nil {
			return nil, err
		}
		pair.phoneKey, err = newCapacityKey()
		if err != nil {
			return nil, err
		}
		pair.approvalKey, err = newCapacityKey()
		if err != nil {
			return nil, err
		}
		grant, err := store.NormalizeRuntimeGrantInput(store.RuntimeGrantInput{Role: "operator", Scope: store.GrantScope{Actions: []string{"host.list", "session.list", "session.read", "command.status"}, Workspaces: []string{pair.workspace}, Sessions: []string{pair.session}}}, time.Now())
		if err != nil {
			return nil, err
		}
		scope, _ := json.Marshal(grant.Scope)
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`insert into users(id,issuer,subject) values($1,$2,$1::uuid::text)`, []any{pair.user, issuer}},
			{`insert into org_memberships(org_id,user_id,role) values($1,$2,'member')`, []any{org, pair.user}},
			{`insert into hosts(id,org_id,alias,state) values($1,$2,'Capacity fixture host','active')`, []any{pair.host, org}},
			{`insert into installations(id,host_id,owner_user_id,public_jwk,public_key_thumbprint) values($1,$2,$3,$4::jsonb,$5)`, []any{pair.installation, pair.host, pair.user, string(pair.hostKey.public), pair.hostKey.jkt}},
			{`insert into runtimes(id,installation_id,profile_ref,protocol_version) values($1,$2,'capacity',1)`, []any{pair.runtime, pair.installation}},
			{`insert into workspaces(id,runtime_id,workspace_ref) values($1,$2,'capacity-workspace')`, []any{pair.workspace, pair.runtime}},
			{`insert into sessions(id,runtime_id,workspace_id,dsh_session_id) values($1,$2,$3,'capacity-session')`, []any{pair.session, pair.runtime, pair.workspace}},
			{`insert into runtime_grants(runtime_id,user_id,role,scope,granted_by) values($1,$2,'operator',$3::jsonb,$2)`, []any{pair.runtime, pair.user, string(scope)}},
			{`insert into devices(id,user_id,name,approval_public_jwk,approval_key_thumbprint,proof_public_jwk,proof_key_thumbprint) values($1,$2,'Capacity fixture phone',$3::jsonb,$4,$5::jsonb,$6)`, []any{pair.device, pair.user, string(pair.approvalKey.public), pair.approvalKey.jkt, string(pair.phoneKey.public), pair.phoneKey.jkt}},
		} {
			if _, err := transaction.ExecContext(ctx, statement.query, statement.args...); err != nil {
				return nil, fmt.Errorf("seed row failed at pair=%d", index)
			}
		}
		pairs[index] = pair
	}
	if err := transaction.Commit(); err != nil {
		return nil, errors.New("seed commit failed")
	}
	return pairs, nil
}

func capacityMetrics(client *http.Client, origin string) (map[string]*dto.MetricFamily, string, error) {
	response, err := client.Get(origin + "/metrics")
	if err != nil {
		return nil, "", errors.New("metrics transport failed")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	_ = response.Body.Close()
	if err != nil || response.StatusCode != 200 || len(raw) > 1<<20 {
		return nil, "", errors.New("metrics response failed")
	}
	parser := expfmt.NewTextParser(model.UTF8Validation)
	families, err := parser.TextToMetricFamilies(bytes.NewReader(raw))
	if err != nil {
		return nil, "", errors.New("metrics parse failed")
	}
	return families, string(raw), nil
}

func capacityMetric(families map[string]*dto.MetricFamily, name string, labels map[string]string) float64 {
	for _, metric := range families[name].GetMetric() {
		if len(metric.Label) != len(labels) {
			continue
		}
		match := true
		for _, label := range metric.Label {
			if labels[label.GetName()] != label.GetValue() {
				match = false
			}
		}
		if match {
			if metric.Gauge != nil {
				return metric.GetGauge().GetValue()
			}
			if metric.Counter != nil {
				return metric.GetCounter().GetValue()
			}
			if metric.Histogram != nil {
				return float64(metric.GetHistogram().GetSampleCount())
			}
		}
	}
	return 0
}

func capacityServerResources(families map[string]*dto.MetricFamily) map[string]float64 {
	result := map[string]float64{}
	for _, name := range []string{"process_cpu_seconds_total", "process_resident_memory_bytes", "process_open_fds", "go_goroutines", "go_memstats_heap_alloc_bytes", "dsh_remote_relay_subscriptions"} {
		result[name] = capacityMetric(families, name, nil)
	}
	for _, role := range []string{"installation", "device"} {
		result[role+"_active"] = capacityMetric(families, "dsh_remote_relay_connections", map[string]string{"role": role, "phase": "active"})
		result[role+"_queued_bytes"] = capacityMetric(families, "dsh_remote_relay_queued_bytes", map[string]string{"role": role})
	}
	return result
}

func capacityWait(ctx context.Context, limit time.Duration, condition func() (bool, error)) error {
	deadline := time.Now().Add(limit)
	for {
		done, err := condition()
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("capacity condition timed out")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func TestAuthenticatedRelayCapacity(t *testing.T) {
	rawConfig := os.Getenv("REMOTE_TEST_RELAY_CAPACITY_CONFIG")
	if rawConfig == "" {
		t.Skip("explicit isolated authenticated capacity probe required")
	}
	var config capacityConfig
	decoder := json.NewDecoder(strings.NewReader(rawConfig))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&config) != nil || config.validate() != nil {
		t.Fatal("invalid capacity configuration")
	}
	cluster, output, binary := os.Getenv("REMOTE_TEST_CLUSTER_ROOT"), os.Getenv("REMOTE_TEST_RELAY_CAPACITY_OUTPUT"), os.Getenv("REMOTE_TEST_SERVICE_BIN")
	if cluster == "" || binary == "" || !strings.HasPrefix(os.Getenv("REMOTE_TEST_DATABASE_URL"), "host="+cluster+" ") {
		t.Fatal("private isolated cluster and service binary required")
	}
	repo, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	output, err = filepath.Abs(output)
	if err != nil || !strings.HasPrefix(output, filepath.Join(repo, ".local")+string(os.PathSeparator)) {
		t.Fatal("fresh local evidence directory required")
	}
	if err := os.MkdirAll(filepath.Dir(output), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(output, 0700); err != nil {
		t.Fatal("evidence directory already exists or is unavailable")
	}
	report := map[string]any{"v": 1, "state": "failed", "config": config, "fixture": "production Go process with seeded directory, TLS ingress, signed protocol peers", "tls_min_version": "1.3", "backend": "loopback HTTP", "race": config.Race,
		"database_max_connections": 30, "native_model_processes": 0, "go_version": runtime.Version(), "platform": runtime.GOOS + "/" + runtime.GOARCH, "started_at": time.Now().UTC().Format(time.RFC3339)}
	report["serializable_admissions"] = store.DefaultSerializableAdmissions
	report["thresholds"] = map[string]any{"delivery_p95_ms": 500, "source_max_lag_ms": 250, "final_delivery_wait_seconds": 5, "revocation_seconds": 5, "admission_seconds": 120}
	report["workload"] = map[string]any{"fanout": 1, "merge_window_ms": 0, "source_schedule": "phase-spread fixed interval", "directory": "preprovisioned fixture users, devices and approved runtimes", "identity": "local signed issuer with real resource/DPoP/registered-key verification"}
	phase := "prepare"
	defer func() {
		report["last_phase"] = phase
		report["finished_at"] = time.Now().UTC().Format(time.RFC3339)
		raw, _ := json.MarshalIndent(report, "", "  ")
		if err := os.WriteFile(filepath.Join(output, "summary.json"), append(raw, '\n'), 0600); err != nil {
			t.Error("cannot preserve capacity evidence")
		}
	}()
	var fdLimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &fdLimit); err != nil || fdLimit.Cur < uint64(config.Connections*4+512) {
		t.Fatal("file descriptor budget is insufficient for the explicit TLS workload")
	}
	report["nofile_soft_limit"] = fdLimit.Cur
	for _, artifact := range []struct{ name, path string }{{"service", binary}, {"probe", func() string { path, _ := os.Executable(); return path }()}} {
		info, err := buildinfo.ReadFile(artifact.path)
		if err != nil {
			t.Fatal("cannot inspect capacity binary provenance")
		}
		race := false
		for _, setting := range info.Settings {
			if setting.Key == "-race" {
				race = setting.Value == "true"
			}
		}
		if race != config.Race {
			t.Fatal("capacity race mode does not match actual service/probe binaries")
		}
		report[artifact.name+"_go_version"] = info.GoVersion
	}
	if raw, err := os.ReadFile(binary); err == nil {
		hash := sha256.Sum256(raw)
		report["service_sha256"] = hex.EncodeToString(hash[:])
	}
	if raw, err := exec.Command("git", "-C", repo, "rev-parse", "HEAD").Output(); err == nil {
		report["source_revision"] = strings.TrimSpace(string(raw))
	}
	if raw, err := exec.Command("git", "-C", repo, "status", "--porcelain", "--untracked-files=all").Output(); err == nil {
		var dirty []string
		for _, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
			if len(line) > 3 && line[3:] != "PLAN.md" {
				dirty = append(dirty, line[3:])
			}
		}
		report["source_dirty_files"] = dirty
	}
	fail := func(err error) {
		t.Helper()
		report["failure"] = err.Error()
		t.Fatalf("capacity phase=%s failed: %v", phase, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Minute)
	defer cancel()
	_, db := testsupport.PostgresDatabase(t)
	dsn, err := capacityDatabaseDSN(ctx, db)
	if err != nil {
		fail(errors.New("private database configuration failed"))
	}
	issuerKey, err := newCapacityKey()
	if err != nil {
		fail(err)
	}
	issuerPublic, _ := json.Marshal(jose.JSONWebKey{Key: &issuerKey.private.PublicKey, KeyID: "capacity-issuer", Algorithm: "ES256", Use: "sig"})
	jwks := append(append([]byte(`{"keys":[`), issuerPublic...), []byte(`]}`)...)
	reserve := func() net.Listener {
		t.Helper()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		return listener
	}
	apiReservation, metricsReservation := reserve(), reserve()
	apiAddress, metricsAddress := apiReservation.Addr().String(), metricsReservation.Addr().String()
	target, _ := url.Parse("http://" + apiAddress)
	proxy := httputil.NewSingleHostReverseProxy(target)
	backendTransport := http.DefaultTransport.(*http.Transport).Clone()
	backendTransport.MaxIdleConnsPerHost = 64
	backendTransport.ResponseHeaderTimeout = 10 * time.Second
	proxy.Transport = backendTransport
	defer backendTransport.CloseIdleConnections()
	ingress := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fixture/jwks" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(jwks)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	ingress.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	ingress.StartTLS()
	defer ingress.Close()
	httpClient := ingress.Client()
	transport := httpClient.Transport.(*http.Transport).Clone()
	transport.TLSHandshakeTimeout = 5 * time.Second
	transport.ResponseHeaderTimeout = 10 * time.Second
	transport.MaxIdleConns = 128
	transport.MaxIdleConnsPerHost = 64
	transport.DialContext = (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	httpClient = &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("fixture redirect denied") }}
	defer transport.CloseIdleConnections()
	caFile := filepath.Join(output, "fixture-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ingress.Certificate().Raw}), 0600); err != nil {
		fail(err)
	}
	issuer := ingress.URL + "/issuer"
	phase = "seed"
	t.Logf("phase=%s pairs=%d", phase, config.Connections/2)
	pairs, err := capacitySeed(ctx, db, config.Connections/2, issuer)
	if err != nil {
		fail(err)
	}
	defer func() {
		for _, pair := range pairs {
			pair.hostPeer.close()
			pair.phonePeer.close()
		}
	}()
	stats := &capacityHTTPStats{}
	for _, pair := range pairs {
		for _, entry := range []struct {
			key    capacityKey
			client string
			target **capacityAPI
		}{{pair.hostKey, "capacity-host", &pair.hostAPI}, {pair.phoneKey, "capacity-mobile", &pair.phoneAPI}} {
			now := time.Now()
			token, err := capacitySign(issuerKey, "at+jwt", map[string]any{"iss": issuer, "sub": pair.user, "aud": "urn:dsh-capacity", "client_id": entry.client, "jti": capacityID(), "iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(), "scope": "remote.access", "cnf": map[string]any{"jkt": entry.key.jkt}}, map[jose.HeaderKey]any{"kid": "capacity-issuer"})
			if err != nil {
				fail(err)
			}
			*entry.target = &capacityAPI{http: httpClient, origin: ingress.URL, token: token, key: entry.key, stats: stats}
		}
	}
	serviceLog, err := os.OpenFile(filepath.Join(output, "service.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		fail(err)
	}
	defer serviceLog.Close()
	_ = apiReservation.Close()
	_ = metricsReservation.Close()
	command := exec.CommandContext(ctx, binary)
	command.Env = []string{"PATH=" + os.Getenv("PATH"), "SSL_CERT_FILE=" + caFile, "REMOTE_ISSUER=" + issuer, "REMOTE_AUDIENCE=urn:dsh-capacity", "REMOTE_JWKS_URL=" + ingress.URL + "/fixture/jwks", "REMOTE_CLIENT_IDS=capacity-host,capacity-mobile", "REMOTE_HOST_CLIENT_IDS=capacity-host", "REMOTE_REQUIRED_SCOPES=remote.access", "REMOTE_PUBLIC_ORIGIN=" + ingress.URL, "REMOTE_DATABASE_URL=" + dsn, "REMOTE_LISTEN_ADDR=" + apiAddress, "REMOTE_METRICS_LISTEN_ADDR=" + metricsAddress}
	command.Stdout, command.Stderr = serviceLog, serviceLog
	if err := command.Start(); err != nil {
		fail(errors.New("service process failed to start"))
	}
	processDone := make(chan error, 1)
	go func() { processDone <- command.Wait() }()
	stopped := false
	defer func() {
		if !stopped {
			_ = command.Process.Signal(syscall.SIGTERM)
			select {
			case <-processDone:
			case <-time.After(6 * time.Second):
				_ = command.Process.Kill()
				<-processDone
			}
		}
	}()
	metricsClient := &http.Client{Timeout: 3 * time.Second}
	defer metricsClient.CloseIdleConnections()
	metricsOrigin := "http://" + metricsAddress
	phase = "readiness"
	if err := capacityWait(ctx, 10*time.Second, func() (bool, error) {
		response, err := httpClient.Get(ingress.URL + "/readyz")
		if err != nil {
			return false, nil
		}
		_ = response.Body.Close()
		return response.StatusCode == 204, nil
	}); err != nil {
		fail(err)
	}
	type sample struct {
		Phase   string             `json:"phase"`
		Elapsed float64            `json:"elapsed_seconds"`
		Server  map[string]float64 `json:"server"`
		Driver  map[string]float64 `json:"driver"`
	}
	var samples []sample
	started := time.Now()
	snapshot := func(name string) (map[string]*dto.MetricFamily, error) {
		families, body, err := capacityMetrics(metricsClient, metricsOrigin)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(output, name+".prom"), []byte(body), 0600); err != nil {
			return nil, err
		}
		samples = append(samples, sample{name, time.Since(started).Seconds(), capacityServerResources(families), capacityOwnResources()})
		return families, nil
	}
	defer func() {
		if report["state"] != "passed" {
			_, _ = snapshot("failed")
		}
		report["samples"] = samples
		codes := map[string]int64{}
		for code := 100; code < 600; code++ {
			if count := stats.codes[code].Load(); count != 0 {
				codes[strconv.Itoa(code)] = count
			}
		}
		report["http_status_counts"] = codes
		stats.mu.Lock()
		report["http_roundtrip_ms"] = capacityQuantiles(stats.durations)
		stats.mu.Unlock()
		var sent, received int64
		var sentBytes, receivedBytes int64
		for _, pair := range pairs {
			sent += pair.sent.Load()
			received += pair.received.Load()
			sentBytes += pair.sentProtocolBytes.Load()
			receivedBytes += pair.receivedProtocolBytes.Load()
		}
		report["source_frames"], report["delivered_frames"] = sent, received
		report["source_protocol_bytes"], report["delivered_protocol_bytes"] = sentBytes, receivedBytes
	}()
	if _, err := snapshot("before"); err != nil {
		fail(err)
	}
	failures := make(chan error, config.Connections+16)
	checks := map[string]bool{}
	phase = "negative-controls"
	t.Logf("phase=%s", phase)
	if err := pairs[0].admit(ctx, ctx, httpClient, ingress.URL, failures, true, pairs[1].runtime, checks); err != nil {
		fail(err)
	}
	report["negative_controls"] = checks
	phase = "admission"
	t.Logf("phase=%s target_connections=%d workers=%d", phase, config.Connections, config.Workers)
	var admittedPairs atomic.Int64
	admittedPairs.Store(1)
	admission := make([]time.Duration, len(pairs))
	admitted := time.Now()
	admitCtx, stopAdmission := context.WithTimeout(ctx, 120*time.Second)
	err = capacityParallel(admitCtx, len(pairs)-1, config.Workers, func(operation context.Context, index int) error {
		index++
		begin := time.Now()
		err := pairs[index].admit(operation, ctx, httpClient, ingress.URL, failures, false, "", nil)
		admission[index] = time.Since(begin)
		if err == nil {
			current := admittedPairs.Add(1)
			if current%100 == 0 || current == int64(len(pairs)) {
				t.Logf("admitted_pairs=%d/%d", current, len(pairs))
			}
		}
		return err
	})
	stopAdmission()
	report["admission_seconds"] = time.Since(admitted).Seconds()
	report["pair_admission_ms"] = capacityQuantiles(admission[1:])
	if err != nil {
		fail(err)
	}
	if err := capacityWait(ctx, 5*time.Second, func() (bool, error) {
		families, _, err := capacityMetrics(metricsClient, metricsOrigin)
		if err != nil {
			return false, err
		}
		for _, role := range []string{"installation", "device"} {
			if capacityMetric(families, "dsh_remote_relay_connections", map[string]string{"role": role, "phase": "active"}) != float64(len(pairs)) {
				return false, nil
			}
		}
		return true, nil
	}); err != nil {
		fail(err)
	}
	if _, err := snapshot("ready"); err != nil {
		fail(err)
	}
	phase = "subscriptions"
	err = capacityParallel(ctx, config.ActivePairs, config.Workers, func(_ context.Context, index int) error {
		pair := pairs[index]
		if err := pair.phonePeer.send(capacityWire{V: 1, Type: "session.subscribe", RequestID: capacityID(), RuntimeID: pair.runtime, SessionID: pair.session, Payload: json.RawMessage(`{}`)}); err != nil {
			return err
		}
		for _, ready := range []chan struct{}{pair.phonePeer.snapshots, pair.phonePeer.starts} {
			select {
			case <-ready:
			case <-time.After(5 * time.Second):
				return errors.New("stream setup timed out")
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	})
	if err != nil {
		fail(err)
	}
	phase = "hold"
	holdStart := time.Now()
	bodyMarker := "CAPACITY_PRIVATE_" + capacityID()
	text := bodyMarker + strings.Repeat("x", config.PayloadBytes-len(bodyMarker))
	for _, pair := range pairs[:config.ActivePairs] {
		pair.streamMu.Lock()
		pair.body = text
		pair.sendTimes = make([]time.Time, config.HoldSeconds*config.EventsPerSecond)
		pair.delays = make([]time.Duration, len(pair.sendTimes))
		pair.streamMu.Unlock()
	}
	t.Logf("phase=%s seconds=%d active_pairs=%d events_per_second=%d", phase, config.HoldSeconds, config.ActivePairs, config.EventsPerSecond)
	streamDone := make(chan error, 1)
	go func() {
		streamDone <- capacityParallel(ctx, config.ActivePairs, config.ActivePairs, func(_ context.Context, index int) error {
			pair := pairs[index]
			for sequence := 0; sequence < config.HoldSeconds*config.EventsPerSecond; sequence++ {
				interval := time.Second / time.Duration(config.EventsPerSecond)
				deadline := holdStart.Add(time.Duration(sequence)*interval + time.Duration(index)*interval/time.Duration(config.ActivePairs))
				if wait := time.Until(deadline); wait > 0 {
					timer := time.NewTimer(wait)
					select {
					case <-timer.C:
					case <-ctx.Done():
						timer.Stop()
						return ctx.Err()
					}
				}
				lag := time.Since(deadline).Nanoseconds()
				for previous := pair.maxLag.Load(); lag > previous; previous = pair.maxLag.Load() {
					if pair.maxLag.CompareAndSwap(previous, lag) {
						break
					}
				}
				pair.streamMu.Lock()
				pair.sendTimes[sequence] = time.Now()
				frame := capacityWire{V: 1, Type: "assistant.chunk", RequestID: pair.request, RuntimeID: pair.runtime, RuntimeEpoch: pair.epoch, SessionID: pair.session, SubscriptionID: pair.subscription, SyncID: pair.syncID, Payload: capacityPayload(map[string]any{"type": "chunk", "attemptId": pair.attemptID, "revision": 1, "index": sequence, "time": time.Now().UnixMilli(), "chunk": map[string]any{"type": "text-delta", "index": 0, "text": text}})}
				pair.streamMu.Unlock()
				if err := pair.hostPeer.send(frame); err != nil {
					return err
				}
				pair.sent.Add(1)
			}
			return nil
		})
	}()
	holdTimer := time.NewTimer(time.Duration(config.HoldSeconds) * time.Second)
	defer holdTimer.Stop()
	sampleTimer := time.NewTicker(5 * time.Second)
	defer sampleTimer.Stop()
	holding := true
	for holding {
		select {
		case err := <-failures:
			fail(err)
		case <-ctx.Done():
			fail(ctx.Err())
		case <-sampleTimer.C:
			if _, err := snapshot("hold-latest"); err != nil {
				fail(err)
			}
		case <-holdTimer.C:
			holding = false
		}
	}
	if err := <-streamDone; err != nil {
		fail(err)
	}
	if err := capacityWait(ctx, 5*time.Second, func() (bool, error) {
		select {
		case err := <-failures:
			return false, err
		default:
		}
		for _, pair := range pairs[:config.ActivePairs] {
			if pair.received.Load() != int64(config.HoldSeconds*config.EventsPerSecond) {
				return false, nil
			}
		}
		return true, nil
	}); err != nil {
		fail(err)
	}
	report["hold_elapsed_seconds"] = time.Since(holdStart).Seconds()
	var sent, received, maxLag int64
	var deliveryDelays []time.Duration
	minimumHeartbeats := int64(1 << 62)
	for _, pair := range pairs {
		sent += pair.sent.Load()
		received += pair.received.Load()
		maxLag = max(maxLag, pair.maxLag.Load())
		minimumHeartbeats = min(minimumHeartbeats, pair.hostPeer.heartbeats.Load(), pair.phonePeer.heartbeats.Load())
		pair.streamMu.Lock()
		deliveryDelays = append(deliveryDelays, pair.delays...)
		pair.streamMu.Unlock()
	}
	report["source_frames"], report["delivered_frames"], report["source_payload_bytes_per_frame"], report["max_generator_lag_ms"], report["minimum_heartbeats_per_peer"] = sent, received, config.PayloadBytes, float64(maxLag)/1e6, minimumHeartbeats
	minimumRequired := int64(1 + (config.HoldSeconds-1)/15)
	if minimumHeartbeats < minimumRequired {
		fail(errors.New("sustained workload missed mandatory maintenance heartbeats"))
	}
	if sent != int64(config.ActivePairs*config.EventsPerSecond*config.HoldSeconds) || received != sent {
		fail(errors.New("offered or delivered stream count mismatch"))
	}
	delivery := capacityQuantiles(deliveryDelays)
	report["delivery_ms"] = delivery
	if maxLag > int64(250*time.Millisecond) {
		fail(errors.New("load generator exceeded fixed pacing budget"))
	}
	if config.ActivePairs > 0 && delivery["p95"] >= 500 {
		fail(errors.New("end-to-end delivery exceeded fixed p95 budget"))
	}
	loaded, err := snapshot("loaded")
	if err != nil {
		fail(err)
	}
	for _, role := range []string{"installation", "device"} {
		if capacityMetric(loaded, "dsh_remote_relay_connections", map[string]string{"role": role, "phase": "active"}) != float64(len(pairs)) {
			fail(errors.New("steady-state connection count changed"))
		}
	}
	select {
	case err := <-failures:
		fail(err)
	default:
	}
	if config.ActivePairs > 0 {
		var count, within uint64
		for _, metric := range loaded["dsh_remote_relay_session_route_duration_seconds"].GetMetric() {
			histogram := metric.GetHistogram()
			count += histogram.GetSampleCount()
			for _, bucket := range histogram.GetBucket() {
				if bucket.GetUpperBound() == .3 {
					within += bucket.GetCumulativeCount()
				}
			}
		}
		if count == 0 {
			fail(errors.New("missing Go ingress routing observations"))
		}
		ratio := float64(within) / float64(count)
		report["route_samples"], report["route_fraction_le_300ms"] = count, ratio
		if ratio < .95 {
			fail(errors.New("Go ingress routing exceeded fixed 300ms bucket budget"))
		}
	}
	phase = "revocation"
	victim := pairs[len(pairs)-1]
	victim.phonePeer.expectRevocation.Store(true)
	revoked := time.Now()
	if err := victim.phoneAPI.call(ctx, "DELETE", "/v1/devices/"+victim.device, nil, nil, 200); err != nil {
		fail(err)
	}
	select {
	case <-victim.phonePeer.closed:
	case <-time.After(5 * time.Second):
		fail(errors.New("revoked socket did not close"))
	}
	if !victim.phonePeer.revoked.Load() {
		fail(errors.New("missing ordered revocation notice"))
	}
	report["revocation_ms"] = float64(time.Since(revoked)) / float64(time.Millisecond)
	for index := range map[int]bool{0: true, max(0, len(pairs)/2-1): true} {
		if err := pairs[index].hostPeer.heartbeat(); err != nil {
			fail(err)
		}
		if err := pairs[index].phonePeer.heartbeat(); err != nil {
			fail(err)
		}
	}
	revokedMetrics, err := snapshot("revoked")
	if err != nil {
		fail(err)
	}
	if capacityMetric(revokedMetrics, "dsh_remote_relay_connections", map[string]string{"role": "installation", "phase": "active"}) != float64(len(pairs)) || capacityMetric(revokedMetrics, "dsh_remote_relay_connections", map[string]string{"role": "device", "phase": "active"}) != float64(len(pairs)-1) {
		fail(errors.New("revocation affected unrelated connections"))
	}
	select {
	case err := <-failures:
		fail(err)
	default:
	}
	phase = "close"
	closeStart := time.Now()
	if err := capacityParallel(ctx, len(pairs), config.Workers, func(_ context.Context, index int) error {
		pairs[index].hostPeer.close()
		pairs[index].phonePeer.close()
		return nil
	}); err != nil {
		fail(err)
	}
	if err := capacityWait(ctx, 20*time.Second, func() (bool, error) {
		families, _, err := capacityMetrics(metricsClient, metricsOrigin)
		if err != nil {
			return false, err
		}
		for _, role := range []string{"installation", "device"} {
			for _, state := range []string{"handshaking", "active", "closing"} {
				if capacityMetric(families, "dsh_remote_relay_connections", map[string]string{"role": role, "phase": state}) != 0 {
					return false, nil
				}
			}
		}
		if capacityMetric(families, "dsh_remote_relay_subscriptions", nil) != 0 {
			return false, nil
		}
		return true, nil
	}); err != nil {
		fail(err)
	}
	report["close_seconds"] = time.Since(closeStart).Seconds()
	if _, err := snapshot("closed"); err != nil {
		fail(err)
	}
	phase = "database-proof"
	var users, devices, keys, hosts, runtimes, connected int
	if err := db.QueryRowContext(ctx, `select (select count(*) from users),(select count(*) from devices),(select count(distinct proof_key_thumbprint) from devices),(select count(*) from installations),(select count(*) from runtimes),(select count(*) from runtimes where connection_id is not null)`).Scan(&users, &devices, &keys, &hosts, &runtimes, &connected); err != nil {
		fail(errors.New("database final count query failed"))
	}
	if users != len(pairs) || devices != len(pairs) || keys != len(pairs) || hosts != len(pairs) || runtimes != len(pairs) || connected != 0 {
		fail(errors.New("database identity counts or runtime cleanup mismatch"))
	}
	var challenges, credentials int
	if err := db.QueryRowContext(ctx, `select (select count(*) from installation_challenges),(select count(*) from host_connection_credentials)`).Scan(&challenges, &credentials); err != nil || challenges != len(pairs) || credentials != len(pairs) {
		fail(errors.New("metadata retries duplicated durable challenge or credential outcomes"))
	}
	for _, action := range []string{"host.credential.challenge", "host.credential.issue", "host.runtime.connect", "session.catalog.sync", "realtime.ticket.issue", "realtime.ticket.consume"} {
		var count int
		if err := db.QueryRowContext(ctx, `select count(*) from audit_log where action=$1`, action).Scan(&count); err != nil || count != len(pairs) {
			fail(errors.New("metadata admission audit count mismatch"))
		}
	}
	for _, name := range []string{"before", "ready", "loaded", "revoked", "closed"} {
		raw, err := os.ReadFile(filepath.Join(output, name+".prom"))
		if err != nil {
			fail(err)
		}
		if bytes.Contains(raw, []byte(bodyMarker)) {
			fail(errors.New("metrics exposed stream body"))
		}
		for _, pair := range pairs {
			for _, id := range []string{pair.user, pair.runtime, pair.device} {
				if bytes.Contains(raw, []byte(id)) {
					fail(errors.New("metrics exposed resource identity"))
				}
			}
		}
	}
	report["samples"] = samples
	codes := map[string]int64{}
	for code := 100; code < 600; code++ {
		if count := stats.codes[code].Load(); count != 0 {
			codes[strconv.Itoa(code)] = count
		}
	}
	report["http_status_counts"] = codes
	report["http_roundtrip_ms"] = capacityQuantiles(stats.durations)
	phase = "shutdown"
	_ = command.Process.Signal(syscall.SIGTERM)
	select {
	case err := <-processDone:
		stopped = true
		if err != nil {
			fail(errors.New("service shutdown failed"))
		}
	case <-time.After(6 * time.Second):
		fail(errors.New("service shutdown timed out"))
	}
	if raw, err := os.ReadFile(binary); err == nil {
		hash := sha256.Sum256(raw)
		report["service_sha256"] = hex.EncodeToString(hash[:])
	}
	report["state"] = "passed"
	phase = "complete"
	t.Logf("authenticated TLS capacity passed: connections=%d active_pairs=%d source_frames=%d delivered=%d", config.Connections, config.ActivePairs, sent, received)
}
