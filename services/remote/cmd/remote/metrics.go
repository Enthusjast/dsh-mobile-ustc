package main

import (
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"dsh-mobile-ustc/services/remote/internal/observability"
)

type metricsEndpoint struct {
	server   *http.Server
	listener net.Listener
	result   chan error
	finished chan struct{}
}

func startMetricsEndpoint(address string, metrics *observability.Metrics) (*metricsEndpoint, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return nil, nil
	}
	host, port, err := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	number, portErr := strconv.Atoi(port)
	if err != nil || ip == nil || !ip.IsLoopback() || portErr != nil || number < 0 || number > 65535 || metrics == nil {
		return nil, errors.New("remote metrics requires a literal loopback address and valid port")
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, errors.New("remote metrics listener is unavailable")
	}
	endpoint := &metricsEndpoint{listener: listener, result: make(chan error, 1), finished: make(chan struct{}),
		server: &http.Server{Handler: metrics.Handler(), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second,
			WriteTimeout: 3 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8 << 10}}
	go func() {
		defer close(endpoint.finished)
		endpoint.result <- endpoint.server.Serve(listener)
	}()
	return endpoint, nil
}

func (endpoint *metricsEndpoint) errors() <-chan error {
	if endpoint == nil {
		return nil
	}
	return endpoint.result
}

func (endpoint *metricsEndpoint) close() {
	if endpoint == nil {
		return
	}
	_ = endpoint.server.Close()
	<-endpoint.finished
}
