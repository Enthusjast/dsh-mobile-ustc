package files

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestExportManifestBindsSourceEpochAndBytesWithoutWideningPhoneUploads(t *testing.T) {
	host := HostBinding{RuntimeID: "22222222-2222-4222-8222-222222222222", RuntimeEpoch: "44444444-4444-4444-8444-444444444444"}
	input := ExportRegistration{Origin: "session_attachment", RequestID: "11111111-1111-4111-8111-111111111111", RuntimeID: host.RuntimeID, SessionID: "33333333-3333-4333-8333-333333333333", SourceID: "55555555-5555-4555-8555-555555555555", Name: "导出.bin", SizeBytes: MaxExportBytes, SHA256: strings.Repeat("a", 64), SourceExpiresAt: time.Now().Add(time.Minute)}
	first, err := NormalizeExport(input, host)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NormalizeRegistration(UploadRegistration{RequestID: input.RequestID, RuntimeID: input.RuntimeID, SessionID: input.SessionID, Name: input.Name, SizeBytes: input.SizeBytes, SHA256: input.SHA256}); err == nil {
		t.Fatal("large export widened phone uploads")
	}
	for _, field := range []string{"source", "epoch", "name", "size", "sha"} {
		other, identity := input, host
		switch field {
		case "source":
			other.SourceID = input.RequestID
		case "epoch":
			identity.RuntimeEpoch = input.RequestID
		case "name":
			other.Name = "other"
		case "size":
			other.SizeBytes--
		case "sha":
			other.SHA256 = strings.Repeat("b", 64)
		}
		if value, err := NormalizeExport(other, identity); err != nil || value == first {
			t.Fatal("export identity was not bound to its original source/version")
		}
	}
	for _, name := range []string{"../private", "C:\\private", "\x00", strings.Repeat("中", 200)} {
		other := input
		other.Name = name
		if _, err := NormalizeExport(other, host); err == nil {
			t.Fatal("export accepted a path or oversized name")
		}
	}
	input.SizeBytes = MaxExportBytes + 1
	if _, err := NormalizeExport(input, host); err == nil {
		t.Fatal("overlarge export was admitted")
	}
}

func TestExportAndDownloadVerifiersRetainFinalBytesAndCannotReplaceScanAdmission(t *testing.T) {
	body := []byte("exact export bytes")
	reader, err := NewExportVerifiedReader(bytes.NewReader(body), &serviceScan{scanner: &serviceScanner{}, ctx: t.Context()}, int64(len(body)), digest(body))
	if err != nil {
		t.Fatal(err)
	}
	if actual, err := io.ReadAll(reader); err != nil || !bytes.Equal(actual, body) || !reader.Verified() {
		t.Fatal("export verification changed bytes")
	}
	if _, err := NewExportVerifiedReader(bytes.NewReader(nil), nil, 0, digest(nil)); err == nil {
		t.Fatal("export scan accepted a missing scanner")
	}
	broken, err := newDownloadVerifier(bytes.NewReader(body), int64(len(body)), digest([]byte("different")))
	if err != nil {
		t.Fatal(err)
	}
	if actual, err := io.ReadAll(broken); !errors.Is(err, ErrIntegrity) || len(actual) != 0 {
		t.Fatal("download delivered its final bytes before verification")
	}
	storage, _ := s3Fixture(t, &s3Peer{})
	file := serviceFile(body)
	file.CommittedAttempt = file.QuarantineAttempt
	key, _ := file.CommittedKey()
	unscanned, err := newDownloadVerifier(bytes.NewReader(body), int64(len(body)), digest(body))
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.PutVerified(t.Context(), key, unscanned); !errors.Is(err, ErrInvalid) {
		t.Fatal("a read verifier could publish an unscanned object")
	}
	quarantine, _ := file.SourceKey()
	if _, err := storage.PresignUpload(t.Context(), quarantine, MaxExportBytes, digest(body), time.Minute); err == nil {
		t.Fatal("phone upload signer accepted export size")
	}
	if _, err := storage.PresignHostExport(t.Context(), quarantine, MaxExportBytes, digest(body), time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.PresignHostExport(t.Context(), quarantine, 1, digest(body), 6*time.Minute); err == nil {
		t.Fatal("export capability exceeded five minutes")
	}
	for _, sign := range []func(context.Context, ObjectKey, int64, string, time.Duration) (UploadURL, error){storage.PresignUpload, storage.PresignHostExport} {
		capability, err := sign(t.Context(), quarantine, 0, digest(nil), time.Minute)
		if err != nil || capability.Headers["Content-Type"] != "application/octet-stream" {
			t.Fatal("empty signed upload omitted its required binary transport header")
		}
	}
}
