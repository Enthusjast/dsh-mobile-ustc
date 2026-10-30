package store

import (
	"errors"
	"testing"
	"time"
)

func TestPendingEnrollmentExpiryCannotSurviveConfirmationWaits(t *testing.T) {
	for _, operation := range []string{"phone-runtime", "phone-device", "phone-membership", "host-phone-device", "phone-audit", "host-audit", "host-grant-audit"} {
		t.Run(operation, func(t *testing.T) {
			ctx, db, input, enrollment := enrollmentPreviewFixture(t)
			owner := UserIdentity{Issuer: input.Issuer, Subject: input.Subject}
			phone := UserIdentity{Issuer: input.Issuer, Subject: "target-subject"}
			host := operation == "host-phone-device" || operation == "host-audit" || operation == "host-grant-audit"
			if host {
				if _, err := db.ConfirmEnrollmentUser(ctx, phone, "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "proof-jkt-target", enrollment.EnrollmentID, input.Code); err != nil {
					t.Fatal(err)
				}
			}
			if operation == "phone-audit" || operation == "host-audit" || operation == "host-grant-audit" {
				action := "enrollment.user_confirm"
				if operation == "host-audit" {
					action = "enrollment.host_confirm"
				} else if operation == "host-grant-audit" {
					action = "runtime_grant.update"
				}
				if _, err := db.DB.ExecContext(ctx, `create function hold_enrollment_audit() returns trigger language plpgsql as $$ begin
				 if new.action='`+action+`' then perform pg_advisory_xact_lock(426962);end if;return new;end $$;
				 create trigger hold_enrollment_audit before insert on audit_log for each row execute function hold_enrollment_audit()`); err != nil {
					t.Fatal(err)
				}
			}
			gate, err := db.DB.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer gate.Rollback()
			query, fragment := `select pg_advisory_xact_lock(426962)`, "insert into audit_log"
			switch operation {
			case "phone-runtime":
				query, fragment = `select 1 from runtimes where id='`+enrollment.RuntimeID+`' for update`, "for update of e, h, i, r"
			case "phone-device", "host-phone-device":
				query, fragment = `select 1 from devices where id='dddddddd-dddd-4ddd-8ddd-dddddddddddd' for update`, "from devices where id"
			case "phone-membership":
				query, fragment = `select 1 from org_memberships where org_id='`+input.OrganizationID+`' and user_id='66666666-6666-4666-8666-666666666666' for update`, "select role from org_memberships"
			}
			if _, err := gate.ExecContext(ctx, query); err != nil {
				t.Fatal(err)
			}
			var expires time.Time
			if err := db.DB.QueryRowContext(ctx, `update enrollments set expires_at=clock_timestamp()+interval '700 milliseconds' where id=$1 returning expires_at`, enrollment.EnrollmentID).Scan(&expires); err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() {
				var err error
				if host {
					_, err = db.ConfirmEnrollmentHost(ctx, owner, input.InstallationKeyThumbprint, enrollment.EnrollmentID, input.Code, "66666666-6666-4666-8666-666666666666")
				} else {
					_, err = db.ConfirmEnrollmentUser(ctx, phone, "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "proof-jkt-target", enrollment.EnrollmentID, input.Code)
				}
				result <- err
			}()
			waitForGrantLock(t, ctx, db, fragment)
			waitForGrantDatabaseExpiry(t, ctx, db, expires)
			if err := gate.Commit(); err != nil {
				t.Fatal(err)
			}
			if err := <-result; !errors.Is(err, ErrEnrollmentInvalid) {
				t.Fatal("expired pending enrollment survived confirmation wait", err)
			}
			var grants, confirmations int
			var state string
			if err := db.DB.QueryRowContext(ctx, `select state,
			 (select count(*) from runtime_grants where runtime_id=$2),
			 (select count(*) from audit_log where runtime_id=$2 and action in('enrollment.user_confirm','enrollment.host_confirm'))
			 from enrollments where id=$1`, enrollment.EnrollmentID, enrollment.RuntimeID).Scan(&state, &grants, &confirmations); err != nil {
				t.Fatal(err)
			}
			wantConfirmations := 0
			if host {
				wantConfirmations = 1 // Original, still timely phone confirmation.
			}
			if state == "approved" || grants != 0 || confirmations != wantConfirmations {
				t.Fatal("late confirmation left authority or success evidence", state, grants, confirmations)
			}
		})
	}
}

func TestApprovedEnrollmentConfirmationRetriesDoNotReusePairingDeadline(t *testing.T) {
	ctx, db, input, enrollment := enrollmentPreviewFixture(t)
	owner := UserIdentity{Issuer: input.Issuer, Subject: input.Subject}
	phone := UserIdentity{Issuer: input.Issuer, Subject: "target-subject"}
	confirmPhone := func() error {
		_, err := db.ConfirmEnrollmentUser(ctx, phone, "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "proof-jkt-target", enrollment.EnrollmentID, input.Code)
		return err
	}
	confirmHost := func() error {
		_, err := db.ConfirmEnrollmentHost(ctx, owner, input.InstallationKeyThumbprint, enrollment.EnrollmentID, input.Code, "66666666-6666-4666-8666-666666666666")
		return err
	}
	if err := confirmPhone(); err != nil {
		t.Fatal(err)
	}
	if err := confirmHost(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `update enrollments set created_at=clock_timestamp()-interval '10 minutes',expires_at=clock_timestamp()-interval '1 minute' where id=$1`, enrollment.EnrollmentID); err != nil {
		t.Fatal(err)
	}
	if err := confirmPhone(); err != nil {
		t.Fatal("phone could not reconcile approved history", err)
	}
	if err := confirmHost(); err != nil {
		t.Fatal("host could not reconcile approved history", err)
	}
	var confirmations int
	if err := db.DB.QueryRowContext(ctx, `select count(*) from audit_log where runtime_id=$1 and action in('enrollment.user_confirm','enrollment.host_confirm')`, enrollment.RuntimeID).Scan(&confirmations); err != nil || confirmations != 2 {
		t.Fatal("historical retry repeated confirmation", confirmations, err)
	}
}
