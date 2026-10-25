package relay

import (
	"bufio"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/coder/websocket"
)

// Capture only the hijacked transport. A WebSocket close already in progress
// makes a concurrent CloseNow wait for that handshake rather than abort it.
type upgradeWriter struct {
	http.ResponseWriter
	transport net.Conn
}

func (writer *upgradeWriter) Unwrap() http.ResponseWriter { return writer.ResponseWriter }
func (writer *upgradeWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	connection, buffered, err := http.NewResponseController(writer.ResponseWriter).Hijack()
	if err == nil {
		writer.transport = connection
	}
	return connection, buffered, err
}

func forceTransportCloser(connection net.Conn) func() error {
	if secured, ok := connection.(*tls.Conn); ok {
		connection = secured.NetConn()
	}
	if connection == nil {
		return nil
	}
	return connection.Close
}

func (server *Server) retireConnection(live *liveConnection) {
	server.mu.Lock()
	live.closing = true
	server.mu.Unlock()
	live.stop()
}

func (server *Server) closePolicy(live *liveConnection, reason string) {
	server.retireConnection(live)
	closePolicy(live.conn, reason, live.closeTransport)
}

func (server *Server) abortConnection(live *liveConnection) {
	server.retireConnection(live)
	if live.closeTransport != nil {
		_ = live.closeTransport()
	}
	_ = live.conn.CloseNow()
}

func closePolicy(connection *websocket.Conn, reason string, forceClose func() error) {
	if forceClose == nil {
		_ = connection.CloseNow()
		return
	}
	timer := time.AfterFunc(closeHandshakeGrace, func() {
		_ = forceClose()
	})
	defer timer.Stop()
	_ = connection.Close(websocket.StatusPolicyViolation, reason)
}
