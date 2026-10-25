package files

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This is a protocol peer, not a virus engine. Production uses configured clamd;
// none of these fixtures are registered as a default clean scanner.
func clamdPeer(t *testing.T, respond func(net.Conn, []byte) error) (*ClamAV, <-chan error) {
	t.Helper()
	directory, err := os.MkdirTemp("", "dsh-clamd-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	path := filepath.Join(directory, "scan.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	done := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
		command := make([]byte, len("zINSTREAM\x00"))
		if _, err := io.ReadFull(connection, command); err != nil {
			done <- err
			return
		}
		if string(command) != "zINSTREAM\x00" {
			done <- fmt.Errorf("wrong scanner command")
			return
		}
		var data bytes.Buffer
		for {
			var header [4]byte
			if _, err := io.ReadFull(connection, header[:]); err != nil {
				done <- err
				return
			}
			size := binary.BigEndian.Uint32(header[:])
			if size == 0 {
				break
			}
			if size > ChunkBytes {
				done <- fmt.Errorf("unbounded scanner frame")
				return
			}
			if _, err := io.CopyN(&data, connection, int64(size)); err != nil {
				done <- err
				return
			}
		}
		done <- respond(connection, data.Bytes())
	}()
	scanner, err := NewClamAV(ClamAVConfig{Network: "unix", Address: path, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return scanner, done
}

func TestClamAVFramesExactBytesAndAcceptsOnlyOneCompleteCleanReply(t *testing.T) {
	data := bytes.Repeat([]byte("data\x00\xff"), 30_000)
	for _, scenario := range []string{"clean", "found", "limit", "extra", "unterminated", "oversize", "unknown"} {
		t.Run(scenario, func(t *testing.T) {
			scanner, done := clamdPeer(t, func(connection net.Conn, received []byte) error {
				if !bytes.Equal(received, data) {
					return fmt.Errorf("scanner bytes differ")
				}
				reply := "stream: OK\x00"
				switch scenario {
				case "found":
					reply = "stream: Fixture-Malware FOUND\x00"
				case "limit":
					reply = "INSTREAM size limit exceeded. ERROR\x00"
				case "extra":
					reply += "stream: Fixture-Malware FOUND\x00"
				case "unterminated":
					reply = "stream: OK"
				case "oversize":
					reply = strings.Repeat("x", 4097) + "\x00"
				case "unknown":
					reply = "UNKNOWN COMMAND\x00"
				}
				return writeAll(connection, []byte(reply))
			})
			scan, err := scanner.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer scan.Close()
			reader, err := NewVerifiedReader(bytes.NewReader(data), scan, int64(len(data)), digest(data))
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.CopyN(io.Discard, reader, int64(len(data)))
			want := error(ErrScanUnavailable)
			if scenario == "clean" {
				want = nil
			} else if scenario == "found" {
				want = ErrRejected
			}
			if !errors.Is(err, want) || reader.Verified() != (scenario == "clean") {
				t.Fatalf("verdict=%v want=%v verified=%v", err, want, reader.Verified())
			}
			// Oversized/extra replies can encounter the client's intentional early close.
			if peerErr := <-done; peerErr != nil && scenario != "oversize" && scenario != "extra" {
				t.Fatal(peerErr)
			}
		})
	}
}

func TestClamAVCancellationInterruptsAWaitingVerdict(t *testing.T) {
	entered := make(chan struct{})
	scanner, peerDone := clamdPeer(t, func(connection net.Conn, _ []byte) error {
		close(entered)
		var next [1]byte
		_, err := connection.Read(next[:])
		if err != io.EOF {
			return fmt.Errorf("cancelled connection stayed open: %v", err)
		}
		return nil
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	scan, err := scanner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer scan.Close()
	if err := scan.Write([]byte("a")); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- scan.Finish() }()
	<-entered
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, ErrScanUnavailable) {
			t.Fatal(err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("scanner ignored cancellation")
	}
	if err := <-peerDone; err != nil {
		t.Fatal(err)
	}
}

func TestClamAVConfigurationNeverFallsBackToUnverifiedTCPOrClean(t *testing.T) {
	for _, config := range []ClamAVConfig{
		{Network: "unix", Address: "relative.sock", Timeout: time.Second},
		{Network: "tcp", Address: "127.0.0.1:3310", Timeout: time.Second},
		{Network: "tcp", Address: "host:3310", Timeout: time.Second, TLS: &tls.Config{InsecureSkipVerify: true, ServerName: "host"}},
		{Network: "tcp", Address: "host:3310", Timeout: time.Second, TLS: &tls.Config{}},
		{Network: "http", Address: "host:3310", Timeout: time.Second},
		{Network: "unix", Address: "/tmp/scan.sock", Timeout: 0},
	} {
		if _, err := NewClamAV(config); !errors.Is(err, ErrInvalid) {
			t.Fatalf("bad scanner accepted: %v", err)
		}
	}
	scanner, err := NewClamAV(ClamAVConfig{Network: "unix", Address: filepath.Join(t.TempDir(), "absent.sock"), Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scanner.Begin(t.Context()); !errors.Is(err, ErrScanUnavailable) {
		t.Fatal("missing daemon became clean")
	}
}

func TestClamAVTLSVerifiesDaemonIdentityBeforeSendingContent(t *testing.T) {
	certificate := httptest.NewTLSServer(http.NotFoundHandler())
	defer certificate.Close()
	roots := x509.NewCertPool()
	roots.AddCert(certificate.Certificate())
	for _, host := range []string{"127.0.0.1", "wrong.example"} {
		t.Run(host, func(t *testing.T) {
			listener, err := tls.Listen("tcp", "127.0.0.1:0", certificate.TLS)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() {
				connection, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
				command := make([]byte, len("zINSTREAM\x00"))
				if _, err := io.ReadFull(connection, command); err != nil {
					done <- err
					return
				}
				if string(command) != "zINSTREAM\x00" {
					done <- ErrScanUnavailable
					return
				}
				var length [4]byte
				if _, err := io.ReadFull(connection, length[:]); err != nil {
					done <- err
					return
				}
				if binary.BigEndian.Uint32(length[:]) != 1 {
					done <- ErrScanUnavailable
					return
				}
				var data [1]byte
				if _, err := io.ReadFull(connection, data[:]); err != nil {
					done <- err
					return
				}
				if data[0] != 'a' {
					done <- ErrScanUnavailable
					return
				}
				if _, err := io.ReadFull(connection, length[:]); err != nil {
					done <- err
					return
				}
				if binary.BigEndian.Uint32(length[:]) != 0 {
					done <- ErrScanUnavailable
					return
				}
				done <- writeAll(connection, []byte("stream: OK\x00"))
			}()
			scanner, err := NewClamAV(ClamAVConfig{Network: "tcp", Address: listener.Addr().String(), Timeout: time.Second, TLS: &tls.Config{ServerName: host, RootCAs: roots}})
			if err != nil {
				t.Fatal(err)
			}
			scan, err := scanner.Begin(t.Context())
			if host != "127.0.0.1" {
				if !errors.Is(err, ErrScanUnavailable) || scan != nil {
					t.Fatal("wrong TLS daemon became usable")
				}
				if err := <-done; err == nil {
					t.Fatal("file content crossed a failed TLS handshake")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer scan.Close()
			if err := scan.Write([]byte("a")); err != nil {
				t.Fatal(err)
			}
			if err := scan.Finish(); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
