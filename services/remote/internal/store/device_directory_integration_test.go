package store

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestDeviceDirectoryPagesOnlyCurrentAccountAndNeverExportsKeys(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	proof := seedGrantFixture(t, ctx, db.DB)
	const current = "44444444-4444-4444-8444-444444444444"
	const revoked = "88888888-8888-4888-8888-888888888888"
	_, err := db.DB.ExecContext(ctx, `update devices set created_at='2026-01-01T00:00:00Z';
	 insert into devices(id,user_id,name,approval_public_jwk,approval_key_thumbprint,proof_public_jwk,proof_key_thumbprint,created_at,revoked_at)
	 values('88888888-8888-4888-8888-888888888888','22222222-2222-4222-8222-222222222222','old phone','{"private":"PRIVATE_JWK_FIXTURE"}','own-a','{}','own-proof-a','2026-01-01T00:00:00Z',clock_timestamp()),
	 ('99999999-8888-4888-8888-888888888888','22222222-2222-4222-8222-222222222222','other phone','{}','own-b','{}','own-proof-b','2026-01-01T00:00:00Z',null),
	 ('aaaaaaaa-8888-4888-8888-888888888888','22222222-2222-4222-8222-222222222222','latest phone','{}','own-c','{}','own-proof-c','2026-01-01T00:00:00Z',null);
	 update devices set push_provider='fcm',push_token_ciphertext=convert_to('PRIVATE_PUSH_FIXTURE','UTF8') where id='44444444-4444-4444-8444-444444444444';
	 delete from runtime_grants;delete from org_memberships`)
	if err != nil {
		t.Fatal(err)
	}
	identity := UserIdentity{Issuer: "https://id.example.edu", Subject: "owner-subject"}
	first, err := db.ListDevices(ctx, identity, current, proof, 2, "")
	if err != nil || len(first.Items) != 2 || first.NextCursor == nil {
		t.Fatal("first bounded page failed", first, err)
	}
	if first.Items[0].ID != "aaaaaaaa-8888-4888-8888-888888888888" || first.Items[1].ID != "99999999-8888-4888-8888-888888888888" {
		t.Fatal("equal-timestamp device ordering is unstable")
	}
	second, err := db.ListDevices(ctx, identity, current, proof, 2, *first.NextCursor)
	if err != nil || len(second.Items) != 2 || second.NextCursor != nil || second.Items[0].ID != revoked || second.Items[0].State != "revoked" || second.Items[0].RevokedAt == nil || second.Items[1].ID != current || !second.Items[1].Current {
		t.Fatal("device pagination lost revocation or current-key identity", second, err)
	}
	all, err := db.ListDevices(ctx, identity, current, proof, 100, "")
	if err != nil || len(all.Items) != 4 {
		t.Fatal("directory crossed account ownership", err)
	}
	raw, _ := json.Marshal(all)
	for _, private := range []string{"PRIVATE_JWK_FIXTURE", "PRIVATE_PUSH_FIXTURE", "approval_public_jwk", "proof_public_jwk", "push_token", "approval_key_thumbprint", "proof_key_thumbprint"} {
		if strings.Contains(string(raw), private) {
			t.Fatal("directory exported key or provider state")
		}
	}
	var audits int
	if err := db.DB.QueryRowContext(ctx, `select count(*) from audit_log`).Scan(&audits); err != nil || audits != 0 {
		t.Fatal("directory read mutated the account", err)
	}
	if err := db.RevokeDevice(ctx, identity.Issuer, identity.Subject, first.Items[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := db.RevokeDevice(ctx, identity.Issuer, identity.Subject, first.Items[0].ID); err != nil {
		t.Fatal(err)
	}
	listed, err := db.ListDevices(ctx, identity, current, proof, 100, "")
	if err != nil || listed.Items[0].State != "revoked" || !listed.Items[3].Current {
		t.Fatal("listed target could not be retired independently", err)
	}
	if err := db.DB.QueryRowContext(ctx, `select count(*) from audit_log where action='device.revoke'`).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("idempotent directory-target revocation repeated its effect", err)
	}
}

func TestDeviceDirectoryCursorIsNotAuthorityAndRechecksCurrentKey(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	proof := seedGrantFixture(t, ctx, db.DB)
	const current = "44444444-4444-4444-8444-444444444444"
	identity := UserIdentity{Issuer: "https://id.example.edu", Subject: "owner-subject"}
	if _, err := db.DB.ExecContext(ctx, `insert into devices(user_id,name,approval_public_jwk,approval_key_thumbprint,proof_public_jwk,proof_key_thumbprint) values('22222222-2222-4222-8222-222222222222','sibling','{}','sibling-approval','{}','sibling-proof')`); err != nil {
		t.Fatal(err)
	}
	first, err := db.ListDevices(ctx, identity, current, proof, 1, "")
	if err != nil || first.NextCursor == nil {
		t.Fatal(err)
	}
	cursor, err := parseDeviceDirectoryCursor(*first.NextCursor)
	if err != nil {
		t.Fatal(err)
	}
	cursor.UserID = "66666666-6666-4666-8666-666666666666"
	raw, _ := json.Marshal(cursor)
	if _, err := db.ListDevices(ctx, identity, current, proof, 1, base64.RawURLEncoding.EncodeToString(raw)); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("cursor selected another user's devices", err)
	}
	if _, err := db.ListDevices(ctx, UserIdentity{Issuer: identity.Issuer, Subject: "target-subject"}, current, proof, 1, *first.NextCursor); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("account switch reused a prior directory cursor", err)
	}
	if _, err := db.ListDevices(ctx, identity, current, strings.Repeat("A", 43), 1, *first.NextCursor); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("new proof key reused directory authority", err)
	}
	if _, err := db.DB.ExecContext(ctx, `update devices set revoked_at=clock_timestamp() where id=$1`, current); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ListDevices(ctx, identity, current, proof, 1, *first.NextCursor); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("directory read used an earlier active-device check", err)
	}
	if _, err := db.DB.ExecContext(ctx, `update devices set revoked_at=null where id='44444444-4444-4444-8444-444444444444';update users set status='suspended' where subject='owner-subject'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ListDevices(ctx, identity, current, proof, 1, ""); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("suspended account enumerated devices", err)
	}
	if _, err := db.ListDevices(ctx, identity, current, proof, 101, ""); !errors.Is(err, ErrDeviceDirectoryInvalid) {
		t.Fatal("unbounded page accepted", err)
	}
}
