package files

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

const fixtureAccess = "fixture-access"
const fixtureSecret = "fixture-secret"
const fixtureKMS = "fixture-kms-key"

type encryptedObject struct {
	ciphertext, nonce []byte
	sum               string
	size              int64
}
type s3Peer struct {
	mu            sync.Mutex
	objects       map[string]encryptedObject
	aead          cipher.AEAD
	badEncryption bool
	badChecksum   bool
	putFailure    bool
	puts          int
	failure       error
	firstBodyRead chan struct{}
	firstRead     *sync.Once
}

func fixtureCredentials() aws.CredentialsProvider {
	return aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: fixtureAccess, SecretAccessKey: fixtureSecret, Source: "owned-protocol-fixture"}, nil
	})
}
func objectKey(t *testing.T, kind ObjectKind, attempt string) ObjectKey {
	t.Helper()
	key, err := NewObjectKey("11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333", attempt, kind)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
func s3Fixture(t *testing.T, peer *s3Peer) (*S3, *httptest.Server) {
	t.Helper()
	peer.objects = make(map[string]encryptedObject)
	peer.firstRead = &sync.Once{}
	block, err := aes.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	peer.aead, err = cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(peer.serve))
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	storage, err := NewS3(S3Config{Endpoint: server.URL, Region: "fixture-1", Bucket: "remote-fixture", KMSKeyID: fixtureKMS, Roots: roots}, fixtureCredentials())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		peer.mu.Lock()
		defer peer.mu.Unlock()
		if peer.failure != nil {
			t.Error(peer.failure)
		}
	})
	return storage, server
}
func wireValue(request *http.Request, name string) string {
	if value := request.Header.Get(name); value != "" {
		return value
	}
	for key, values := range request.URL.Query() {
		if strings.EqualFold(key, name) && len(values) == 1 {
			return values[0]
		}
	}
	return ""
}
func s3Error(response http.ResponseWriter, status int, code string) {
	response.Header().Set("Content-Type", "application/xml")
	response.WriteHeader(status)
	_, _ = fmt.Fprintf(response, "<Error><Code>%s</Code><Message>fixture</Message></Error>", code)
}
func (peer *s3Peer) serve(response http.ResponseWriter, request *http.Request) {
	if !validS3Signature(request) {
		s3Error(response, 403, "SignatureDoesNotMatch")
		return
	}
	if !strings.HasPrefix(request.URL.Path, "/remote-fixture/remote-files/v1/") {
		s3Error(response, 403, "AccessDenied")
		return
	}
	path := strings.TrimPrefix(request.URL.Path, "/remote-fixture/")
	peer.mu.Lock()
	object, exists := peer.objects[path]
	badEncryption, badChecksum, failPut := peer.badEncryption, peer.badChecksum, peer.putFailure
	firstBodyRead, firstRead := peer.firstBodyRead, peer.firstRead
	if request.Method == "PUT" {
		peer.puts++
	}
	peer.mu.Unlock()
	switch request.Method {
	case "PUT":
		if strings.Contains(path, "/objects/") && request.Header.Get("If-None-Match") != "*" {
			s3Error(response, 400, "InvalidRequest")
			return
		}
		if request.Header.Get("If-None-Match") == "*" && exists {
			s3Error(response, 412, "PreconditionFailed")
			return
		}
		if wireValue(request, "x-amz-server-side-encryption") != "aws:kms" || wireValue(request, "x-amz-server-side-encryption-aws-kms-key-id") != fixtureKMS {
			s3Error(response, 400, "InvalidEncryption")
			return
		}
		body := readerFunc(func(target []byte) (int, error) {
			n, err := request.Body.Read(target)
			if n > 0 && firstBodyRead != nil {
				firstRead.Do(func() { close(firstBodyRead) })
			}
			return n, err
		})
		data, err := io.ReadAll(io.LimitReader(body, 1<<20))
		if err != nil || int64(len(data)) != request.ContentLength {
			s3Error(response, 400, "IncompleteBody")
			return
		}
		sum := sha256.Sum256(data)
		encoded := base64.StdEncoding.EncodeToString(sum[:])
		if wireValue(request, "x-amz-checksum-sha256") != encoded {
			s3Error(response, 400, "BadDigest")
			return
		}
		nonce := make([]byte, peer.aead.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			s3Error(response, 500, "InternalError")
			return
		}
		object = encryptedObject{ciphertext: peer.aead.Seal(nil, nonce, data, []byte(path)), nonce: nonce, size: int64(len(data)), sum: encoded}
		peer.mu.Lock()
		peer.objects[path] = object
		peer.mu.Unlock()
		// Simulate a fully stored object whose response was lost/unavailable.
		if failPut {
			s3Error(response, 503, "ServiceUnavailable")
			return
		}
	case "HEAD", "GET":
		if !exists {
			s3Error(response, 404, "NoSuchKey")
			return
		}
	case "DELETE":
		peer.mu.Lock()
		delete(peer.objects, path)
		peer.mu.Unlock()
		response.WriteHeader(204)
		return
	default:
		s3Error(response, 405, "MethodNotAllowed")
		return
	}
	response.Header().Set("x-amz-server-side-encryption", "aws:kms")
	response.Header().Set("x-amz-server-side-encryption-aws-kms-key-id", fixtureKMS)
	if badEncryption {
		response.Header().Set("x-amz-server-side-encryption", "AES256")
	}
	response.Header().Set("x-amz-checksum-sha256", object.sum)
	if badChecksum {
		response.Header().Set("x-amz-checksum-sha256", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	}
	response.Header().Set("ETag", `"fixture"`)
	if request.Method == "HEAD" || request.Method == "GET" {
		response.Header().Set("Content-Length", strconv.FormatInt(object.size, 10))
	}
	if request.Method == "GET" {
		data, err := peer.aead.Open(nil, object.nonce, object.ciphertext, []byte(path))
		if err != nil {
			peer.mu.Lock()
			peer.failure = errors.New("fixture at-rest authentication failed")
			peer.mu.Unlock()
			return
		}
		_, _ = response.Write(data)
	}
}

func hmac256(key []byte, input string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(input))
	return mac.Sum(nil)
}

// Verify the actual SDK-produced SigV4 authorization, not just its presence.
func validS3Signature(request *http.Request) bool {
	query := request.URL.Query()
	credential, signed, signature, stamp := query.Get("X-Amz-Credential"), query.Get("X-Amz-SignedHeaders"), query.Get("X-Amz-Signature"), query.Get("X-Amz-Date")
	presigned := signature != ""
	if !presigned {
		auth := strings.TrimPrefix(request.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ")
		for _, item := range strings.Split(auth, ", ") {
			name, value, _ := strings.Cut(item, "=")
			switch name {
			case "Credential":
				credential = value
			case "SignedHeaders":
				signed = value
			case "Signature":
				signature = value
			}
		}
		stamp = request.Header.Get("X-Amz-Date")
	} else {
		if query.Get("X-Amz-Algorithm") != "AWS4-HMAC-SHA256" {
			return false
		}
		expires, err := strconv.ParseInt(query.Get("X-Amz-Expires"), 10, 64)
		if err != nil || expires < 1 || expires > 900 {
			return false
		}
		query.Del("X-Amz-Signature")
	}
	parts := strings.Split(credential, "/")
	issued, err := time.Parse("20060102T150405Z", stamp)
	if err != nil || time.Since(issued).Abs() > 2*time.Minute || len(parts) != 5 || parts[0] != fixtureAccess || parts[1] != stamp[:8] || parts[2] != "fixture-1" || parts[3] != "s3" || parts[4] != "aws4_request" {
		return false
	}
	names := strings.Split(signed, ";")
	if signed == "" || !sort.StringsAreSorted(names) {
		return false
	}
	var canonicalHeaders strings.Builder
	for _, name := range names {
		value := request.Header.Get(name)
		if name == "host" {
			value = request.Host
		}
		if name == "content-length" {
			value = strconv.FormatInt(request.ContentLength, 10)
		}
		canonicalHeaders.WriteString(name + ":" + strings.Join(strings.Fields(value), " ") + "\n")
	}
	payload := request.Header.Get("X-Amz-Content-Sha256")
	if payload == "" && presigned {
		payload = "UNSIGNED-PAYLOAD"
	}
	canonicalQuery := strings.ReplaceAll(query.Encode(), "+", "%20")
	canonical := request.Method + "\n" + request.URL.EscapedPath() + "\n" + canonicalQuery + "\n" + canonicalHeaders.String() + "\n" + signed + "\n" + payload
	sum := sha256.Sum256([]byte(canonical))
	scope := strings.Join(parts[1:], "/")
	key := hmac256([]byte("AWS4"+fixtureSecret), parts[1])
	key = hmac256(key, parts[2])
	key = hmac256(key, "s3")
	key = hmac256(key, "aws4_request")
	actual := hex.EncodeToString(hmac256(key, "AWS4-HMAC-SHA256\n"+stamp+"\n"+scope+"\n"+hex.EncodeToString(sum[:])))
	return hmac.Equal([]byte(actual), []byte(signature))
}

func putCapability(t *testing.T, client *http.Client, capability UploadURL, data []byte, expected int) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), capability.Method, capability.URL, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range capability.Headers {
		if !strings.EqualFold(name, "content-length") {
			request.Header.Set(name, value)
		}
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("private capability write failed")
	}
	defer response.Body.Close()
	if response.StatusCode != expected {
		t.Fatalf("capability status=%d want=%d", response.StatusCode, expected)
	}
}

func TestS3QuarantineCapabilityCannotRewriteTheVerifiedObject(t *testing.T) {
	peer := &s3Peer{}
	storage, server := s3Fixture(t, peer)
	quarantine := objectKey(t, Quarantine, "44444444-4444-4444-8444-444444444444")
	committed := objectKey(t, Committed, "55555555-5555-4555-8555-555555555555")
	data := bytes.Repeat([]byte("scanned binary content\x00\xff"), 5000)
	capability, err := storage.PresignUpload(t.Context(), quarantine, int64(len(data)), digest(data), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if capability.Method != "PUT" || strings.Contains(fmt.Sprint(capability), server.URL) {
		t.Fatal("capability representation leaked URL")
	}
	putCapability(t, server.Client(), capability, data, 200)
	// Even a still-live quarantine capability is checksum-bound.
	putCapability(t, server.Client(), capability, bytes.Repeat([]byte("x"), len(data)), 400)
	altered := capability
	altered.URL = strings.Replace(capability.URL, "/quarantine/", "/objects/", 1)
	putCapability(t, server.Client(), altered, data, 403)
	source, err := storage.OpenEncrypted(t.Context(), quarantine, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	scan := &scanFixture{}
	reader, err := NewVerifiedReader(source, scan, int64(len(data)), digest(data))
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.PutVerified(t.Context(), committed, reader); err != nil {
		t.Fatal(err)
	}
	if !reader.Verified() || !bytes.Equal(scan.data.Bytes(), data) {
		t.Fatal("object was not scanned exactly")
	}
	peer.mu.Lock()
	object := peer.objects[committed.value]
	peer.mu.Unlock()
	if bytes.Contains(object.ciphertext, []byte("scanned binary content")) {
		t.Fatal("fixture at-rest content was plaintext")
	}
	decoded, err := peer.aead.Open(nil, object.nonce, object.ciphertext, []byte(committed.value))
	if err != nil || !bytes.Equal(decoded, data) {
		t.Fatal("committed object bytes differ")
	}
	again, _ := NewVerifiedReader(bytes.NewReader(data), &scanFixture{}, int64(len(data)), digest(data))
	if err := storage.PutVerified(t.Context(), committed, again); !errors.Is(err, ErrBlobConflict) {
		t.Fatalf("immutable object overwrite=%v", err)
	}
	if err := storage.Delete(t.Context(), quarantine); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.OpenEncrypted(t.Context(), quarantine, int64(len(data))); !errors.Is(err, ErrBlobUnavailable) {
		t.Fatal("deleted quarantine still visible")
	}
}

func TestS3CannotConfirmFailedScansOrMissingEncryptionEvidence(t *testing.T) {
	for _, scenario := range []string{"rejected", "hash", "encryption", "checksum", "lost-response", "empty"} {
		t.Run(scenario, func(t *testing.T) {
			peer := &s3Peer{badEncryption: scenario == "encryption", badChecksum: scenario == "checksum", putFailure: scenario == "lost-response"}
			storage, _ := s3Fixture(t, peer)
			key := objectKey(t, Committed, "44444444-4444-4444-8444-444444444444")
			data := []byte("private transfer")
			scan, expected, want := &scanFixture{}, digest(data), error(nil)
			switch scenario {
			case "rejected":
				scan.finishErr = ErrRejected
				want = ErrRejected
			case "hash":
				expected = strings.Repeat("0", 64)
				want = ErrIntegrity
			case "encryption":
				want = ErrEncryption
			case "checksum":
				want = ErrIntegrity
			case "lost-response":
				want = ErrBlobUnavailable
			case "empty":
				data = nil
				expected = digest(nil)
			}
			reader, err := NewVerifiedReader(bytes.NewReader(data), scan, int64(len(data)), expected)
			if err != nil {
				t.Fatal(err)
			}
			if err := storage.PutVerified(t.Context(), key, reader); !errors.Is(err, want) {
				t.Fatalf("write=%v want=%v", err, want)
			}
			peer.mu.Lock()
			puts := peer.puts
			peer.mu.Unlock()
			if puts > 1 {
				t.Fatal("streaming write was automatically replayed")
			}
		})
	}
}

func TestS3StreamsBeforeFinalScanAndDoesNotCopyAnOverwrittenQuarantine(t *testing.T) {
	peer := &s3Peer{firstBodyRead: make(chan struct{})}
	storage, server := s3Fixture(t, peer)
	quarantine := objectKey(t, Quarantine, "44444444-4444-4444-8444-444444444444")
	committed := objectKey(t, Committed, "55555555-5555-4555-8555-555555555555")
	data := bytes.Repeat([]byte("original bytes"), 30_000)
	capability, err := storage.PresignUpload(t.Context(), quarantine, int64(len(data)), digest(data), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	putCapability(t, server.Client(), capability, data, 200)
	// Observe the committed PUT separately from the original browser upload.
	peer.mu.Lock()
	peer.firstBodyRead = make(chan struct{})
	peer.firstRead = &sync.Once{}
	firstBodyRead := peer.firstBodyRead
	peer.mu.Unlock()
	source, err := storage.OpenEncrypted(t.Context(), quarantine, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	// A separate writer can change the quarantine object after GET opened.
	replaced := bytes.Repeat([]byte("x"), len(data))
	nonce := make([]byte, peer.aead.NonceSize())
	_, _ = rand.Read(nonce)
	peer.mu.Lock()
	peer.objects[quarantine.value] = encryptedObject{ciphertext: peer.aead.Seal(nil, nonce, replaced, []byte(quarantine.value)), nonce: nonce, size: int64(len(replaced)), sum: base64.StdEncoding.EncodeToString(make([]byte, 32))}
	peer.mu.Unlock()
	scan := &scanFixture{finish: func() error {
		select {
		case <-firstBodyRead:
			return nil
		case <-time.After(time.Second):
			return ErrScanUnavailable
		}
	}}
	reader, err := NewVerifiedReader(source, scan, int64(len(data)), digest(data))
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.PutVerified(t.Context(), committed, reader); err != nil {
		t.Fatal(err)
	}
	peer.mu.Lock()
	object := peer.objects[committed.value]
	peer.mu.Unlock()
	actual, err := peer.aead.Open(nil, object.nonce, object.ciphertext, []byte(committed.value))
	if err != nil || !bytes.Equal(actual, data) {
		t.Fatal("post-scan copy used a different source object")
	}
}

func TestS3DoesNotForwardAuthenticationAcrossRedirects(t *testing.T) {
	var forwarded atomic.Int64
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { forwarded.Add(1) }))
	defer target.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	roots := x509.NewCertPool()
	roots.AddCert(redirect.Certificate())
	roots.AddCert(target.Certificate())
	storage, err := NewS3(S3Config{Endpoint: redirect.URL, Region: "fixture-1", Bucket: "remote-fixture", KMSKeyID: fixtureKMS, Roots: roots}, fixtureCredentials())
	if err != nil {
		t.Fatal(err)
	}
	key := objectKey(t, Quarantine, "44444444-4444-4444-8444-444444444444")
	if _, err := storage.OpenEncrypted(t.Context(), key, 0); !errors.Is(err, ErrBlobUnavailable) {
		t.Fatal("redirect was accepted as a content response")
	}
	if forwarded.Load() != 0 {
		t.Fatal("storage credentials followed an external redirect")
	}
}

func TestS3RejectsUnscopedKeysUnverifiedEndpointsAndCommittedUploadCapabilities(t *testing.T) {
	storage, _ := s3Fixture(t, &s3Peer{})
	committed := objectKey(t, Committed, "44444444-4444-4444-8444-444444444444")
	if _, err := storage.PresignUpload(t.Context(), committed, 0, digest(nil), time.Minute); !errors.Is(err, ErrInvalid) {
		t.Fatal("committed object received an upload capability")
	}
	if _, err := NewObjectKey("../tenant", "", "", "", Quarantine); !errors.Is(err, ErrInvalid) {
		t.Fatal("client path became an object key")
	}
	for _, endpoint := range []string{"http://localhost", "https://user:secret@localhost", "https://localhost/path", "https://localhost?query", "https://localhost#fragment"} {
		if _, err := NewS3(S3Config{Endpoint: endpoint, Region: "fixture-1", Bucket: "remote-fixture", KMSKeyID: fixtureKMS}, fixtureCredentials()); !errors.Is(err, ErrInvalid) {
			t.Fatal("unverified endpoint accepted")
		}
	}
	for _, kms := range []string{"", "bad\r\n", "bad\x01", "中"} {
		if _, err := NewS3(S3Config{Endpoint: "https://localhost", Region: "fixture-1", Bucket: "remote-fixture", KMSKeyID: kms}, fixtureCredentials()); !errors.Is(err, ErrInvalid) {
			t.Fatal("missing/invalid explicit KMS key accepted")
		}
	}
	if _, err := storage.OpenEncrypted(t.Context(), ObjectKey{}, 0); !errors.Is(err, ErrInvalid) {
		t.Fatal("zero key was readable")
	}
}
