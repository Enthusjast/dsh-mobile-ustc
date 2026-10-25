package files

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

var ErrBlobUnavailable = errors.New("files: object storage unavailable")
var ErrEncryption = errors.New("files: object encryption was not verified")
var ErrBlobConflict = errors.New("files: object already exists")

var objectUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var bucketName = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
var regionName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

type ObjectKind string

const Quarantine ObjectKind = "quarantine"
const Committed ObjectKind = "objects"

// ObjectKey can only be constructed from server-owned resource and attempt IDs.
// A quarantine PUT capability never names the eventual committed object.
type ObjectKey struct {
	value string
	kind  ObjectKind
}

// StorageKey is persisted only by the server metadata repository.
func (key ObjectKey) StorageKey() string { return key.value }

func NewObjectKey(org, session, file, attempt string, kind ObjectKind) (ObjectKey, error) {
	if kind != Quarantine && kind != Committed {
		return ObjectKey{}, ErrInvalid
	}
	for _, id := range []string{org, session, file, attempt} {
		if !objectUUID.MatchString(id) {
			return ObjectKey{}, ErrInvalid
		}
	}
	return ObjectKey{value: "remote-files/v1/" + string(kind) + "/" + org + "/" + session + "/" + file + "/" + attempt, kind: kind}, nil
}

type S3Config struct {
	Endpoint string
	Region   string
	Bucket   string
	KMSKeyID string
	// Optional explicit trust roots, also used by the isolated TLS protocol fixture.
	Roots *x509.CertPool
}

type S3 struct {
	client    *s3.Client
	presigner *s3.PresignClient
	config    S3Config
}

func NewS3(config S3Config, credentials aws.CredentialsProvider) (*S3, error) {
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" || endpoint.RawPath != "" || endpoint.Path != "" && endpoint.Path != "/" ||
		!regionName.MatchString(config.Region) || !bucketName.MatchString(config.Bucket) || strings.Contains(config.Bucket, "..") || net.ParseIP(config.Bucket) != nil || credentials == nil ||
		len(config.KMSKeyID) == 0 || len(config.KMSKeyID) > 1024 || strings.ContainsFunc(config.KMSKeyID, func(c rune) bool { return c <= 0x20 || c >= 0x7f }) {
		return nil, ErrInvalid
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: config.Roots}
	client := s3.NewFromConfig(aws.Config{
		Region: config.Region, Credentials: credentials,
		HTTPClient:                 &http.Client{Transport: transport, Timeout: 15 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		RetryMaxAttempts:           1,
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
	}, func(options *s3.Options) {
		options.BaseEndpoint = aws.String(config.Endpoint)
		options.UsePathStyle = true
	})
	return &S3{client: client, presigner: s3.NewPresignClient(client), config: config}, nil
}

// UploadURL is a short-lived bearer capability. Never log or persist its URL.
type UploadURL struct {
	URL       string            `json:"url"`
	Method    string            `json:"method"`
	Headers   map[string]string `json:"headers"`
	ExpiresAt time.Time         `json:"expires_at"`
}

func (UploadURL) String() string   { return "files.UploadURL" }
func (UploadURL) GoString() string { return "files.UploadURL" }

func checksum(digest string) (string, bool) {
	bytes, err := hex.DecodeString(digest)
	if err != nil || len(bytes) != 32 || hex.EncodeToString(bytes) != digest {
		return "", false
	}
	return base64.StdEncoding.EncodeToString(bytes), true
}

func (storage *S3) PresignUpload(ctx context.Context, key ObjectKey, size int64, digest string, lifetime time.Duration) (UploadURL, error) {
	sum, valid := checksum(digest)
	if key.value == "" || key.kind != Quarantine || size < 0 || size > MaxUploadBytes || !valid || lifetime < time.Second || lifetime > 15*time.Minute || lifetime%time.Second != 0 {
		return UploadURL{}, ErrInvalid
	}
	request, err := storage.presigner.PresignPutObject(ctx, storage.putInput(key, size, sum), s3.WithPresignExpires(lifetime))
	if err != nil {
		return UploadURL{}, ErrBlobUnavailable
	}
	headers := make(map[string]string)
	for name, values := range request.SignedHeader {
		if len(values) != 1 {
			return UploadURL{}, ErrBlobUnavailable
		}
		if strings.EqualFold(name, "host") {
			continue
		}
		headers[name] = values[0]
	}
	location, err := url.Parse(request.URL)
	if err != nil {
		return UploadURL{}, ErrBlobUnavailable
	}
	issued, err := time.Parse("20060102T150405Z", location.Query().Get("X-Amz-Date"))
	if err != nil || location.Query().Get("X-Amz-Expires") != strconv.FormatInt(int64(lifetime/time.Second), 10) {
		return UploadURL{}, ErrBlobUnavailable
	}
	return UploadURL{URL: request.URL, Method: request.Method, Headers: headers, ExpiresAt: issued.Add(lifetime)}, nil
}

func (storage *S3) putInput(key ObjectKey, size int64, sum string) *s3.PutObjectInput {
	return &s3.PutObjectInput{
		Bucket: aws.String(storage.config.Bucket), Key: aws.String(key.value), ContentLength: aws.Int64(size),
		ContentType: aws.String("application/octet-stream"), CacheControl: aws.String("no-store"), ChecksumSHA256: aws.String(sum),
		ServerSideEncryption: types.ServerSideEncryptionAwsKms, SSEKMSKeyId: aws.String(storage.config.KMSKeyID),
	}
}

// PutVerified performs one immutable write of exactly the scanned stream. It
// never copies a mutable quarantine object after scanning a different GET.
func (storage *S3) PutVerified(ctx context.Context, key ObjectKey, reader *VerifiedReader) error {
	if key.value == "" || key.kind != Committed || reader == nil || reader.failure != nil || reader.read != 0 {
		return ErrInvalid
	}
	sum, valid := checksum(reader.digest)
	if !valid {
		return ErrInvalid
	}
	input := storage.putInput(key, reader.size, sum)
	input.Body, input.IfNoneMatch = reader, aws.String("*")
	result, err := storage.client.PutObject(ctx, input, func(options *s3.Options) {
		// The exact SHA-256 is already bound in the checksum header, and TLS is
		// mandatory. A streaming source must not be rewound for payload signing.
		options.APIOptions = append(options.APIOptions, v4.SwapComputePayloadSHA256ForUnsignedPayloadMiddleware)
	})
	if err != nil {
		if reader.failure != nil {
			return reader.failure
		}
		var apiError smithy.APIError
		if errors.As(err, &apiError) && (apiError.ErrorCode() == "PreconditionFailed" || apiError.ErrorCode() == "ConditionalRequestConflict") {
			return ErrBlobConflict
		}
		return ErrBlobUnavailable
	}
	if !reader.Verified() {
		return ErrIntegrity
	}
	if result.ServerSideEncryption != types.ServerSideEncryptionAwsKms || aws.ToString(result.SSEKMSKeyId) != storage.config.KMSKeyID {
		return ErrEncryption
	}
	if aws.ToString(result.ChecksumSHA256) != sum {
		return ErrIntegrity
	}
	stored, err := storage.client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(storage.config.Bucket), Key: aws.String(key.value), ChecksumMode: types.ChecksumModeEnabled})
	if err != nil {
		return ErrBlobUnavailable
	}
	if stored.ContentLength == nil || *stored.ContentLength != reader.size || aws.ToString(stored.ChecksumSHA256) != sum {
		return ErrIntegrity
	}
	if stored.ServerSideEncryption != types.ServerSideEncryptionAwsKms || aws.ToString(stored.SSEKMSKeyId) != storage.config.KMSKeyID {
		return ErrEncryption
	}
	return nil
}

// OpenEncrypted is private to the transfer service. Callers still verify the
// actual bytes against their authorized manifest, including during downloads.
func (storage *S3) OpenEncrypted(ctx context.Context, key ObjectKey, size int64) (io.ReadCloser, error) {
	if key.value == "" || size < 0 || size > MaxUploadBytes {
		return nil, ErrInvalid
	}
	result, err := storage.client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(storage.config.Bucket), Key: aws.String(key.value), ChecksumMode: types.ChecksumModeEnabled})
	if err != nil {
		return nil, ErrBlobUnavailable
	}
	if result.ContentLength == nil || *result.ContentLength != size {
		_ = result.Body.Close()
		return nil, ErrIntegrity
	}
	if result.ServerSideEncryption != types.ServerSideEncryptionAwsKms || aws.ToString(result.SSEKMSKeyId) != storage.config.KMSKeyID {
		_ = result.Body.Close()
		return nil, ErrEncryption
	}
	return result.Body, nil
}

func (storage *S3) Delete(ctx context.Context, key ObjectKey) error {
	if key.value == "" {
		return ErrInvalid
	}
	_, err := storage.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(storage.config.Bucket), Key: aws.String(key.value)})
	if err != nil {
		return ErrBlobUnavailable
	}
	return nil
}

// Used by the private capability consumer to reproduce a signed known length.
func (request UploadURL) ContentLength() (int64, bool) {
	for name, value := range request.Headers {
		if strings.EqualFold(name, "content-length") {
			size, err := strconv.ParseInt(value, 10, 64)
			return size, err == nil && size >= 0
		}
	}
	return 0, false
}
