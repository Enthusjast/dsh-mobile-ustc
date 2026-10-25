package files

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type ClamAVConfig struct {
	// A local Unix socket, or TLS over TCP with verified server identity.
	Network string
	Address string
	TLS     *tls.Config
	Timeout time.Duration
}

type ClamAV struct{ config ClamAVConfig }

func NewClamAV(config ClamAVConfig) (*ClamAV, error) {
	if config.Timeout < time.Second || config.Timeout > 15*time.Minute {
		return nil, ErrInvalid
	}
	if config.Network == "unix" {
		if !filepath.IsAbs(config.Address) || config.TLS != nil {
			return nil, ErrInvalid
		}
	} else if config.Network == "tcp" {
		host, _, err := net.SplitHostPort(config.Address)
		if err != nil || host == "" || config.TLS == nil || config.TLS.InsecureSkipVerify || config.TLS.ServerName == "" {
			return nil, ErrInvalid
		}
		config.TLS = config.TLS.Clone()
		config.TLS.MinVersion = max(config.TLS.MinVersion, tls.VersionTLS12)
	} else {
		return nil, ErrInvalid
	}
	return &ClamAV{config: config}, nil
}

func (scanner *ClamAV) Begin(ctx context.Context) (Scan, error) {
	if ctx.Err() != nil {
		return nil, ErrScanUnavailable
	}
	deadline := time.Now().Add(scanner.config.Timeout)
	if parent, ok := ctx.Deadline(); ok && parent.Before(deadline) {
		deadline = parent
	}
	dialer := &net.Dialer{Deadline: deadline}
	var connection net.Conn
	var err error
	if scanner.config.Network == "tcp" {
		connection, err = (&tls.Dialer{NetDialer: dialer, Config: scanner.config.TLS}).DialContext(ctx, "tcp", scanner.config.Address)
	} else {
		connection, err = dialer.DialContext(ctx, "unix", scanner.config.Address)
	}
	if err != nil {
		return nil, ErrScanUnavailable
	}
	if err := connection.SetDeadline(deadline); err != nil {
		_ = connection.Close()
		return nil, ErrScanUnavailable
	}
	scan := &clamScan{connection: connection, ctx: ctx}
	scan.stop = context.AfterFunc(ctx, func() { _ = connection.Close() })
	if err := writeAll(connection, []byte("zINSTREAM\x00")); err != nil {
		_ = scan.Close()
		return nil, ErrScanUnavailable
	}
	return scan, nil
}

type clamScan struct {
	connection net.Conn
	ctx        context.Context
	stop       func() bool
	once       sync.Once
	finished   bool
}

func (scan *clamScan) Write(data []byte) error {
	if scan.finished || scan.ctx.Err() != nil || len(data) == 0 || len(data) > ChunkBytes {
		return ErrScanUnavailable
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(data)))
	if writeAll(scan.connection, prefix[:]) != nil || writeAll(scan.connection, data) != nil {
		return ErrScanUnavailable
	}
	return nil
}

func (scan *clamScan) Finish() error {
	if scan.finished || scan.ctx.Err() != nil {
		return ErrScanUnavailable
	}
	scan.finished = true
	defer scan.Close()
	if writeAll(scan.connection, []byte{0, 0, 0, 0}) != nil {
		return ErrScanUnavailable
	}
	reader := bufio.NewReaderSize(scan.connection, 4096)
	reply, err := reader.ReadSlice(0)
	if err != nil || len(reply) > 4096 {
		return ErrScanUnavailable
	}
	text := string(reply[:len(reply)-1])
	if strings.HasPrefix(text, "stream: ") && strings.HasSuffix(text, " FOUND") {
		return ErrRejected
	}
	if text != "stream: OK" {
		return ErrScanUnavailable
	}
	// Non-session clamd commands close their connection after the reply. An
	// additional record, an unterminated result or an unavailable daemon is
	// never equivalent to a single clean verdict.
	if _, err := reader.ReadByte(); err != io.EOF {
		return ErrScanUnavailable
	}
	if scan.ctx.Err() != nil {
		return ErrScanUnavailable
	}
	return nil
}

func (scan *clamScan) Close() error {
	scan.once.Do(func() {
		if scan.stop != nil {
			scan.stop()
		}
		_ = scan.connection.Close()
	})
	return nil
}

func writeAll(writer io.Writer, bytes []byte) error {
	for len(bytes) > 0 {
		n, err := writer.Write(bytes)
		if n < 0 || n > len(bytes) {
			return io.ErrShortWrite
		}
		bytes = bytes[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
