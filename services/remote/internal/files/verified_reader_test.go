package files

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

type scanFixture struct {
	data                bytes.Buffer
	finishCount         int
	writeErr, finishErr error
	finish              func() error
}

func (scan *scanFixture) Write(data []byte) error {
	if scan.writeErr != nil {
		return scan.writeErr
	}
	_, err := scan.data.Write(data)
	return err
}
func (scan *scanFixture) Finish() error {
	scan.finishCount++
	if scan.finish != nil {
		return scan.finish()
	}
	return scan.finishErr
}
func (scan *scanFixture) Close() error { return nil }

type writerFunc func([]byte) (int, error)

func (writer writerFunc) Write(data []byte) (int, error) { return writer(data) }

type readerFunc func([]byte) (int, error)

func (reader readerFunc) Read(data []byte) (int, error) { return reader(data) }

func TestDeclaredLengthConsumerCannotSkipIntegrityOrScanSettlement(t *testing.T) {
	data := bytes.Repeat([]byte("binary\x00\xff"), 20_000)
	for _, scenario := range []string{"clean", "hash", "short", "long", "rejected", "unavailable"} {
		t.Run(scenario, func(t *testing.T) {
			source, expected, declared := data, digest(data), int64(len(data))
			scan := &scanFixture{}
			want := error(nil)
			switch scenario {
			case "hash":
				expected = strings.Repeat("0", 64)
				want = ErrIntegrity
			case "short":
				declared++
				want = ErrIntegrity
			case "long":
				source = append(bytes.Clone(data), 'x')
				want = ErrIntegrity
			case "rejected":
				scan.finishErr = ErrRejected
				want = ErrRejected
			case "unavailable":
				scan.finishErr = errors.New("PRIVATE_SCANNER_DETAIL")
				want = ErrScanUnavailable
			}
			reader, err := NewVerifiedReader(bytes.NewReader(source), scan, declared, expected)
			if err != nil {
				t.Fatal(err)
			}
			var stored bytes.Buffer
			// HTTP object clients can stop after exactly this many bytes and
			// never ask the body reader for EOF.
			_, err = io.CopyN(&stored, reader, declared)
			if !errors.Is(err, want) {
				t.Fatalf("result=%v want=%v", err, want)
			}
			if want == nil {
				if !reader.Verified() || !bytes.Equal(stored.Bytes(), data) || !bytes.Equal(scan.data.Bytes(), data) || scan.finishCount != 1 {
					t.Fatal("clean bytes and proof diverged")
				}
			} else {
				if reader.Verified() || int64(stored.Len()) >= declared {
					t.Fatal("failed content completed its declared object body")
				}
				if _, again := reader.Read(make([]byte, 1)); !errors.Is(again, want) {
					t.Fatalf("terminal failure changed: %v", again)
				}
			}
		})
	}
}

func TestFinalChunkStaysUnavailableWhileScannerIsWaiting(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 2*ChunkBytes+3)
	entered, release := make(chan struct{}), make(chan struct{})
	scan := &scanFixture{finish: func() error { close(entered); <-release; return ErrRejected }}
	reader, err := NewVerifiedReader(bytes.NewReader(data), scan, int64(len(data)), digest(data))
	if err != nil {
		t.Fatal(err)
	}
	var written atomic.Int64
	done := make(chan error, 1)
	go func() {
		_, err := io.CopyN(writerFunc(func(data []byte) (int, error) { written.Add(int64(len(data))); return len(data), nil }), reader, int64(len(data)))
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("scanner did not receive the stream")
	}
	before := written.Load()
	if before == 0 || before >= int64(len(data)) {
		t.Fatal("storage did not retain a pending final chunk")
	}
	close(release)
	if err := <-done; !errors.Is(err, ErrRejected) {
		t.Fatal(err)
	}
	if written.Load() != before || reader.Verified() {
		t.Fatal("rejected final chunk escaped")
	}
}

func TestEmptyObjectsMustFinishScanningBeforeAnyStorageCall(t *testing.T) {
	scan := &scanFixture{}
	reader, err := NewVerifiedReader(bytes.NewReader(nil), scan, 0, digest(nil))
	if err != nil || !reader.Verified() || scan.finishCount != 1 || scan.data.Len() != 0 {
		t.Fatalf("empty file=%v", err)
	}
	for _, scenario := range []string{"extra", "bad-hash", "rejected"} {
		source, hash := []byte(nil), digest(nil)
		scan = &scanFixture{}
		want := ErrIntegrity
		switch scenario {
		case "extra":
			source = []byte("unexpected")
		case "bad-hash":
			hash = strings.Repeat("0", 64)
		case "rejected":
			scan.finishErr = ErrRejected
			want = ErrRejected
		}
		if _, err := NewVerifiedReader(bytes.NewReader(source), scan, 0, hash); !errors.Is(err, want) {
			t.Fatalf("%s=%v", scenario, err)
		}
	}
}

func TestInvalidMetadataAndBrokenReadersNeverYieldUnverifiedSuccess(t *testing.T) {
	for _, size := range []int64{-1, MaxUploadBytes + 1} {
		if _, err := NewVerifiedReader(bytes.NewReader(nil), &scanFixture{}, size, digest(nil)); !errors.Is(err, ErrInvalid) {
			t.Fatal(err)
		}
	}
	for _, value := range []string{"short", strings.ToUpper(digest(nil))} {
		if _, err := NewVerifiedReader(bytes.NewReader(nil), &scanFixture{}, 0, value); !errors.Is(err, ErrInvalid) {
			t.Fatal(err)
		}
	}
	for _, source := range []io.Reader{
		readerFunc(func([]byte) (int, error) { return 0, nil }),
		readerFunc(func([]byte) (int, error) { return 0, errors.New("PRIVATE_SOURCE_DETAIL") }),
		readerFunc(func([]byte) (int, error) { return -1, nil }),
		readerFunc(func(target []byte) (int, error) { return len(target) + 1, nil }),
	} {
		reader, err := NewVerifiedReader(source, &scanFixture{}, 1, digest([]byte("a")))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(reader); !errors.Is(err, ErrSource) || reader.Verified() {
			t.Fatal("broken source accepted")
		}
	}
	scan := &scanFixture{writeErr: errors.New("PRIVATE_SCANNER_DETAIL")}
	reader, err := NewVerifiedReader(strings.NewReader("a"), scan, 1, digest([]byte("a")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(reader); !errors.Is(err, ErrScanUnavailable) || scan.finishCount != 0 {
		t.Fatal("failed scanner write was accepted")
	}
}
