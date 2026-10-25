package files

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestFileManifestDigestRetainsLiteralNameAndTargetAndRejectsPaths(t *testing.T) {
	input := UploadRegistration{RequestID: "11111111-1111-4111-8111-111111111111", RuntimeID: "22222222-2222-4222-8222-222222222222", SessionID: "33333333-3333-4333-8333-333333333333", Name: "资料🙂.txt", SizeBytes: 1, SHA256: digest([]byte("a"))}
	original, err := NormalizeRegistration(input)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"target", "name", "size", "hash"} {
		other := input
		switch change {
		case "target":
			other.SessionID = input.RuntimeID
		case "name":
			other.Name = "different.txt"
		case "size":
			other.SizeBytes++
		case "hash":
			other.SHA256 = digest([]byte("b"))
		}
		current, err := NormalizeRegistration(other)
		if err != nil || current == original {
			t.Fatalf("unbound %s", change)
		}
	}
	for _, name := range []string{"../private", "C:\\private", "\x00", "\x85", strings.Repeat("中", 200), ".", ".."} {
		other := input
		other.Name = name
		if _, err := NormalizeRegistration(other); err == nil {
			t.Fatalf("unsafe name accepted")
		}
	}
	changed := input
	changed.RequestID = input.RuntimeID
	if repeated, err := NormalizeRegistration(changed); err != nil || repeated != original {
		t.Fatal("idempotency identity leaked into content digest")
	}
}

func TestFileLimitsAndPublicMetadataDoNotSerializeWorkerAuthority(t *testing.T) {
	limits := Limits{OrganizationBytes: 1000, UserBytes: 400, SessionBytes: 200, OrganizationFiles: 20, UserFiles: 10, SessionFiles: 4, UploadURLTTL: time.Minute, AbandonAfter: time.Hour, RetainFor: 24 * time.Hour}
	if err := limits.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"bytes", "count", "url", "retention"} {
		bad := limits
		switch change {
		case "bytes":
			bad.UserBytes = 1
		case "count":
			bad.OrganizationFiles = 1
		case "url":
			bad.UploadURLTTL = 16 * time.Minute
		case "retention":
			bad.RetainFor = 91 * 24 * time.Hour
		}
		if bad.Validate() == nil {
			t.Fatal("unbounded limits accepted")
		}
	}
	record := Record{ID: "public", Name: "display", State: "scanning", ProofKeyJKT: "PRIVATE_KEY_BINDING", QuarantineAttempt: "PRIVATE_UPLOAD", CommittedAttempt: "PRIVATE_CANDIDATE", RequestSHA256: "PRIVATE_COMMAND"}
	raw, err := json.Marshal(record)
	if err != nil || strings.Contains(string(raw), "PRIVATE") {
		t.Fatal("private metadata leaked")
	}
	claim := ScanClaim{File: record, LeaseID: "PRIVATE_LEASE"}
	raw, _ = json.Marshal(claim)
	if string(raw) != "{}" {
		t.Fatal("scan authority became public JSON")
	}
	if strings.Contains(fmt.Sprintf("%#v %#v", record, claim), "PRIVATE") {
		t.Fatal("formatted metadata exposed private authority")
	}
}
