package store

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func identitySnapshotFixture(t *testing.T, revision int64) IdentitySnapshot {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	return IdentitySnapshot{Version: 1, Complete: true, OperationID: approvalTestUUID(t), DatabaseEpoch: OriginalDatabaseEpoch, Issuer: "https://id.example.edu", ExpectedRevision: revision - 1, Revision: revision, CapturedAt: now.Add(-time.Second), ExpiresAt: now.Add(10 * time.Minute),
		Organizations: []IdentityOrganization{{ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Slug: "test-org", Name: "Test org"}, {ID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", Slug: "other-org", Name: "Other org"}},
		Users: []RecoveryUser{{Subject: "owner-subject", Status: "active", Memberships: []RecoveryMembership{{OrganizationID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Role: "member"}}},
			{Subject: "target-subject", Status: "active", Memberships: []RecoveryMembership{{OrganizationID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Role: "member"}}},
			{Subject: "outsider-subject", Status: "active", Memberships: []RecoveryMembership{{OrganizationID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", Role: "member"}}}}}
}

func TestIdentitySnapshotNormalizationPinsScopeAndDoesNotAliasCallerData(t *testing.T) {
	input := identitySnapshotFixture(t, 1)
	normalized, fingerprint, err := normalizeIdentitySnapshot(input, input.DatabaseEpoch, input.Issuer)
	if err != nil || len(fingerprint) != 64 {
		t.Fatal("valid snapshot rejected", err)
	}
	input.Users[0].Memberships[0].Role = "admin"
	input.Organizations[0].Name = "changed"
	for _, user := range normalized.Users {
		if user.Subject == "owner-subject" && user.Memberships[0].Role != "member" {
			t.Fatal("normalized snapshot retained mutable caller membership")
		}
	}
	if normalized.Organizations[0].Name != "Test org" {
		t.Fatal("normalized snapshot retained mutable organization")
	}
	for _, mutate := range []func(*IdentitySnapshot){
		func(s *IdentitySnapshot) { s.Complete = false }, func(s *IdentitySnapshot) { s.Revision = 3 }, func(s *IdentitySnapshot) { s.ExpectedRevision = -1 },
		func(s *IdentitySnapshot) { s.Users = nil }, func(s *IdentitySnapshot) { s.Organizations = nil }, func(s *IdentitySnapshot) { s.Users = append(s.Users, s.Users[0]) },
		func(s *IdentitySnapshot) { s.Users[0].Status = "deleted" }, func(s *IdentitySnapshot) {
			s.Users[0].Memberships[0].OrganizationID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
		},
		func(s *IdentitySnapshot) { s.Organizations[1].Slug = s.Organizations[0].Slug }, func(s *IdentitySnapshot) { s.Users[0].Subject = "invalid\nsubject" },
		func(s *IdentitySnapshot) { s.ExpiresAt = s.CapturedAt.Add(16 * time.Minute) }, func(s *IdentitySnapshot) { s.Issuer = "http://untrusted.example" },
	} {
		s := identitySnapshotFixture(t, 1)
		mutate(&s)
		if _, _, err := normalizeIdentitySnapshot(s, OriginalDatabaseEpoch, "https://id.example.edu"); !errors.Is(err, ErrIdentitySnapshot) {
			t.Fatal("invalid snapshot accepted", err)
		}
	}
	ordered := identitySnapshotFixture(t, 1)
	_, first, _ := normalizeIdentitySnapshot(ordered, ordered.DatabaseEpoch, ordered.Issuer)
	ordered.Users[0], ordered.Users[1] = ordered.Users[1], ordered.Users[0]
	ordered.Organizations[0], ordered.Organizations[1] = ordered.Organizations[1], ordered.Organizations[0]
	_, second, _ := normalizeIdentitySnapshot(ordered, ordered.DatabaseEpoch, ordered.Issuer)
	if first != second {
		t.Fatal("ordering changed the synchronization fingerprint")
	}
	if _, err := json.Marshal(normalized); err != nil {
		t.Fatal(err)
	}
}
