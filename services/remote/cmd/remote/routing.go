package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"dsh-mobile-ustc/services/remote/internal/relay"
	"dsh-mobile-ustc/services/remote/internal/store"
)

var errRelayConfiguration = errors.New("remote private relay configuration is invalid")

type relayDeployment struct {
	ListenAddr          string `json:"listen_addr"`
	Origin              string `json:"origin"`
	CAFile              string `json:"ca_file"`
	CertificateFile     string `json:"certificate_file"`
	KeyFile             string `json:"key_file"`
	MaxProxyConnections int    `json:"max_proxy_connections"`
	clientTLS           *tls.Config
	serverTLS           *tls.Config
}

func loadRelayDeployment(path, nodeID string) (*relayDeployment, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := readProtectedFile(path, 16<<10)
	if err != nil {
		return nil, errRelayConfiguration
	}
	var config relayDeployment
	if strictFileJSON(raw, &config) != nil || !store.ValidRelayOrigin(config.Origin) || nodeID == "" {
		return nil, errRelayConfiguration
	}
	host, port, err := net.SplitHostPort(config.ListenAddr)
	ip := net.ParseIP(host)
	number, portErr := strconv.Atoi(port)
	if err != nil || ip == nil || (!ip.IsPrivate() && !ip.IsLoopback()) || portErr != nil || number < 1 || number > 65535 {
		return nil, errRelayConfiguration
	}
	if config.MaxProxyConnections == 0 {
		config.MaxProxyConnections = 4096
	}
	if config.MaxProxyConnections < 1 || config.MaxProxyConnections > 12000 {
		return nil, errRelayConfiguration
	}
	read := func(name string) ([]byte, error) {
		if name == "" {
			return nil, errRelayConfiguration
		}
		return readProtectedFile(relativeFile(path, name), 64<<10)
	}
	ca, err := read(config.CAFile)
	if err != nil {
		return nil, errRelayConfiguration
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errRelayConfiguration
	}
	certificate, err := read(config.CertificateFile)
	if err != nil {
		return nil, errRelayConfiguration
	}
	key, err := read(config.KeyFile)
	if err != nil {
		return nil, errRelayConfiguration
	}
	defer clear(key)
	pair, err := tls.X509KeyPair(certificate, key)
	if err != nil || len(pair.Certificate) == 0 {
		return nil, errRelayConfiguration
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || leaf.IsCA {
		return nil, errRelayConfiguration
	}
	node, err := relay.RelayCertificateNode(leaf)
	if err != nil || node != nodeID {
		return nil, errRelayConfiguration
	}
	intermediates := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, errRelayConfiguration
		}
		intermediates.AddCert(cert)
	}
	origin, _ := url.Parse(config.Origin)
	for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: origin.Hostname(), KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
			return nil, errRelayConfiguration
		}
	}
	pair.Leaf = leaf
	config.clientTLS = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{pair}}
	config.serverTLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, Certificates: []tls.Certificate{pair}, NextProtos: []string{"http/1.1"}}
	return &config, nil
}

type relayEndpoint struct {
	server   *http.Server
	result   chan error
	finished chan struct{}
}

func startRelayEndpoint(config *relayDeployment, handler http.Handler) (*relayEndpoint, error) {
	if config == nil {
		return nil, nil
	}
	listener, err := net.Listen("tcp", config.ListenAddr)
	if err != nil {
		return nil, errors.New("remote private relay listener is unavailable")
	}
	endpoint := &relayEndpoint{result: make(chan error, 1), finished: make(chan struct{}), server: &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}}
	go func() {
		defer close(endpoint.finished)
		endpoint.result <- endpoint.server.Serve(tls.NewListener(listener, config.serverTLS))
	}()
	return endpoint, nil
}

func (endpoint *relayEndpoint) errors() <-chan error {
	if endpoint == nil {
		return nil
	}
	return endpoint.result
}
func (endpoint *relayEndpoint) close() {
	if endpoint == nil {
		return
	}
	_ = endpoint.server.Close()
	<-endpoint.finished
}
