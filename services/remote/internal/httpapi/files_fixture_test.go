package httpapi_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/files"
	"github.com/aws/aws-sdk-go-v2/aws"
)

// These are explicitly configured protocol peers. SigV4 cryptography and TLS
// identity rejection are also checked by the files package's storage tests.
type fileWireObject struct {
	ciphertext, nonce []byte
	size              int64
	checksum          string
}
type fileObjectPeer struct {
	mu            sync.Mutex
	objects       map[string]fileWireObject
	aead          cipher.AEAD
	blockGet      bool
	blockHeaders  bool
	pauseAfter    int
	getStarted    chan struct{}
	getCancelled  chan struct{}
	getOnce       sync.Once
	anonymousPuts atomic.Int32
}

func newFileObjectPeer(t *testing.T) (*fileObjectPeer, *files.S3, *httptest.Server) {
	t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	block, err := aes.NewCipher(key)
	clear(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	peer := &fileObjectPeer{objects: make(map[string]fileWireObject), aead: aead, getStarted: make(chan struct{}), getCancelled: make(chan struct{})}
	server := httptest.NewTLSServer(http.HandlerFunc(peer.serve))
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	storage, err := files.NewS3(files.S3Config{Endpoint: server.URL, Region: "fixture-1", Bucket: "remote-files", KMSKeyID: "fixture-kms", Roots: roots}, aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "fixture-access", SecretAccessKey: "fixture-secret", Source: "owned-file-fixture"}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	return peer, storage, server
}
func fileWireValue(request *http.Request, name string) string {
	if value := request.Header.Get(name); value != "" {
		return value
	}
	for key, value := range request.URL.Query() {
		if strings.EqualFold(key, name) && len(value) == 1 {
			return value[0]
		}
	}
	return ""
}
func fileObjectError(response http.ResponseWriter, status int, code string) {
	response.Header().Set("Content-Type", "application/xml")
	response.WriteHeader(status)
	_, _ = fmt.Fprintf(response, "<Error><Code>%s</Code><Message>fixture</Message></Error>", code)
}
func (peer *fileObjectPeer) serve(response http.ResponseWriter, request *http.Request) {
	if request.Header.Get("Authorization") == "" && request.URL.Query().Get("X-Amz-Signature") == "" {
		fileObjectError(response, 403, "AccessDenied")
		return
	}
	if !strings.HasPrefix(request.URL.Path, "/remote-files/remote-files/v1/") {
		fileObjectError(response, 403, "AccessDenied")
		return
	}
	peer.mu.Lock()
	object, exists := peer.objects[request.URL.Path]
	blockGet := peer.blockGet
	blockHeaders := peer.blockHeaders
	pauseAfter := peer.pauseAfter
	peer.mu.Unlock()
	if request.Method == "DELETE" {
		peer.mu.Lock()
		delete(peer.objects, request.URL.Path)
		peer.mu.Unlock()
		response.WriteHeader(204)
		return
	}
	if request.Method == "PUT" {
		if request.Header.Get("If-None-Match") == "*" && exists {
			fileObjectError(response, 412, "PreconditionFailed")
			return
		}
		if strings.Contains(request.URL.Path, "/objects/") && request.Header.Get("If-None-Match") != "*" {
			fileObjectError(response, 400, "InvalidRequest")
			return
		}
		if fileWireValue(request, "x-amz-server-side-encryption") != "aws:kms" || fileWireValue(request, "x-amz-server-side-encryption-aws-kms-key-id") != "fixture-kms" {
			fileObjectError(response, 400, "InvalidEncryption")
			return
		}
		body, err := io.ReadAll(io.LimitReader(request.Body, 1<<20))
		if err != nil || int64(len(body)) != request.ContentLength {
			fileObjectError(response, 400, "IncompleteBody")
			return
		}
		sum := sha256.Sum256(body)
		checksum := base64.StdEncoding.EncodeToString(sum[:])
		if fileWireValue(request, "x-amz-checksum-sha256") != checksum {
			fileObjectError(response, 400, "BadDigest")
			return
		}
		nonce := make([]byte, peer.aead.NonceSize())
		_, _ = rand.Read(nonce)
		object = fileWireObject{ciphertext: peer.aead.Seal(nil, nonce, body, []byte(request.URL.Path)), nonce: nonce, size: int64(len(body)), checksum: checksum}
		peer.mu.Lock()
		peer.objects[request.URL.Path] = object
		peer.mu.Unlock()
		if request.Header.Get("Authorization") == "" {
			peer.anonymousPuts.Add(1)
		}
	} else if !exists {
		fileObjectError(response, 404, "NoSuchKey")
		return
	}
	response.Header().Set("x-amz-server-side-encryption", "aws:kms")
	response.Header().Set("x-amz-server-side-encryption-aws-kms-key-id", "fixture-kms")
	response.Header().Set("x-amz-checksum-sha256", object.checksum)
	response.Header().Set("ETag", `"fixture"`)
	if request.Method == "GET" || request.Method == "HEAD" {
		response.Header().Set("Content-Length", strconv.FormatInt(object.size, 10))
	}
	if request.Method == "GET" {
		if blockHeaders {
			peer.getOnce.Do(func() { close(peer.getStarted) })
			<-request.Context().Done()
			close(peer.getCancelled)
			return
		}
		response.WriteHeader(200)
		if flush, ok := response.(http.Flusher); ok {
			flush.Flush()
		}
		if blockGet {
			peer.getOnce.Do(func() { close(peer.getStarted) })
			<-request.Context().Done()
			close(peer.getCancelled)
			return
		}
		body, err := peer.aead.Open(nil, object.nonce, object.ciphertext, []byte(request.URL.Path))
		if err != nil {
			return
		}
		if pauseAfter > 0 && pauseAfter < len(body) {
			_, _ = response.Write(body[:pauseAfter])
			if flush, ok := response.(http.Flusher); ok {
				flush.Flush()
			}
			peer.getOnce.Do(func() { close(peer.getStarted) })
			<-request.Context().Done()
			close(peer.getCancelled)
			return
		}
		_, _ = response.Write(body)
	}
}

func newFileScannerPeer(t *testing.T) (*files.ClamAV, string) {
	t.Helper()
	directory, err := os.MkdirTemp("", "dsh-file-av-")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", filepath.Join(directory, "scan.sock"))
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
				command := make([]byte, len("zINSTREAM\x00"))
				if _, err := io.ReadFull(connection, command); err != nil || string(command) != "zINSTREAM\x00" {
					return
				}
				var body bytes.Buffer
				for {
					var size [4]byte
					if _, err := io.ReadFull(connection, size[:]); err != nil {
						return
					}
					length := binary.BigEndian.Uint32(size[:])
					if length == 0 {
						break
					}
					if length > files.ChunkBytes || body.Len()+int(length) > 1<<20 {
						return
					}
					if _, err := io.CopyN(&body, connection, int64(length)); err != nil {
						return
					}
				}
				reply := "stream: OK\x00"
				if bytes.Equal(body.Bytes(), files.ScannerTestPattern()) || bytes.HasPrefix(body.Bytes(), []byte("REJECT")) {
					reply = "stream: Fixture-Signature FOUND\x00"
				}
				_, _ = connection.Write([]byte(reply))
			}()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-stopped; workers.Wait(); _ = os.RemoveAll(directory) })
	scanner, err := files.NewClamAV(files.ClamAVConfig{Network: "unix", Address: filepath.Join(directory, "scan.sock"), Timeout: 8 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return scanner, filepath.Join(directory, "scan.sock")
}
