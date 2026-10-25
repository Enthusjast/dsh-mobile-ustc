// Package files owns streamed transfer admission; database metadata never contains file bodies.
package files

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
)

const MaxUploadBytes int64 = 200_000_000
const ChunkBytes = 64 << 10

var (
	ErrInvalid         = errors.New("files: invalid transfer")
	ErrIntegrity       = errors.New("files: content integrity mismatch")
	ErrSource          = errors.New("files: source unavailable")
	ErrScanUnavailable = errors.New("files: scanner unavailable")
	ErrRejected        = errors.New("files: content rejected")
)

// Scan is one independent scanner invocation. Close aborts unfinished scans.
type Scan interface {
	Write([]byte) error
	Finish() error
	Close() error
}

// VerifiedReader withholds the final chunk until size, actual SHA-256 and scan
// settlement all pass. A consumer that stops at Content-Length cannot skip the
// checks by declining to read EOF. The caller owns the source and Scan lifetime.
type VerifiedReader struct {
	source     io.Reader
	scan       Scan
	hash       hash.Hash
	digest     string
	size, read int64
	verified   bool
	failure    error
	zeroReads  int
}

func NewVerifiedReader(source io.Reader, scan Scan, size int64, digest string) (*VerifiedReader, error) {
	if scan == nil {
		return nil, ErrInvalid
	}
	return newContentVerifier(source, scan, size, digest, MaxUploadBytes)
}

func NewExportVerifiedReader(source io.Reader, scan Scan, size int64, digest string) (*VerifiedReader, error) {
	if scan == nil {
		return nil, ErrInvalid
	}
	return newContentVerifier(source, scan, size, digest, MaxExportBytes)
}

// Only used after current authorization proves a committed, scanned export.
// S3.PutVerified rejects this scan-less reader as a publication source.
func newDownloadVerifier(source io.Reader, size int64, digest string) (*VerifiedReader, error) {
	return newContentVerifier(source, nil, size, digest, MaxExportBytes)
}

func newContentVerifier(source io.Reader, scan Scan, size int64, digest string, limit int64) (*VerifiedReader, error) {
	decoded, err := hex.DecodeString(digest)
	if source == nil || size < 0 || size > limit || err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != digest {
		return nil, ErrInvalid
	}
	reader := &VerifiedReader{source: source, scan: scan, hash: sha256.New(), size: size, digest: digest}
	// HTTP clients are allowed to never read a zero-length body.
	if size == 0 {
		if err := reader.finish(false); err != nil {
			return nil, err
		}
	}
	return reader, nil
}

func (reader *VerifiedReader) Verified() bool { return reader.verified && reader.failure == nil }

func (reader *VerifiedReader) fail(err error) (int, error) {
	reader.failure = err
	return 0, err
}

func (reader *VerifiedReader) Read(target []byte) (int, error) {
	if reader.failure != nil {
		return 0, reader.failure
	}
	if reader.verified {
		return 0, io.EOF
	}
	if len(target) == 0 {
		return 0, nil
	}
	limit := min(len(target), ChunkBytes, int(reader.size-reader.read))
	n, err := reader.source.Read(target[:limit])
	if n < 0 || n > limit {
		return reader.fail(ErrSource)
	}
	if n == 0 && err == nil {
		reader.zeroReads++
		if reader.zeroReads >= 100 {
			return reader.fail(ErrSource)
		}
		return 0, nil
	}
	reader.zeroReads = 0
	if err != nil && err != io.EOF {
		return reader.fail(ErrSource)
	}
	if n > 0 {
		_, _ = reader.hash.Write(target[:n])
		if reader.scan != nil {
			if err := reader.scan.Write(target[:n]); err != nil {
				return reader.fail(scanError(err))
			}
		}
		reader.read += int64(n)
	}
	if reader.read < reader.size {
		if err == io.EOF {
			return reader.fail(ErrIntegrity)
		}
		return n, nil
	}
	if err := reader.finish(err == io.EOF); err != nil {
		return reader.fail(err)
	}
	return n, nil
}

func (reader *VerifiedReader) finish(eof bool) error {
	if !eof {
		var extra [1]byte
		for attempts := 0; ; attempts++ {
			n, err := reader.source.Read(extra[:])
			if n < 0 || n > 1 {
				return ErrSource
			}
			if n > 0 {
				return ErrIntegrity
			}
			if err == io.EOF {
				break
			}
			if err != nil || attempts >= 99 {
				return ErrSource
			}
		}
	}
	if reader.read != reader.size || hex.EncodeToString(reader.hash.Sum(nil)) != reader.digest {
		return ErrIntegrity
	}
	if reader.scan != nil {
		if err := reader.scan.Finish(); err != nil {
			return scanError(err)
		}
	}
	reader.verified = true
	return nil
}

func scanError(err error) error {
	if errors.Is(err, ErrRejected) {
		return ErrRejected
	}
	return ErrScanUnavailable
}
