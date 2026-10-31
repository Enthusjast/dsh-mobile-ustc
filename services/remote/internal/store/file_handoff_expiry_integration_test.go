package store

import (
	"errors"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/files"
	"dsh-mobile-ustc/services/remote/internal/observability"
)

func TestFileHandoffDeadlinesCannotSurviveMutationOrAuditWaits(t *testing.T) {
	for _, operation := range []string{"offer", "renew", "read", "stage", "read-update", "stage-outbox"} {
		for _, expiry := range []string{"credential", "file", "grant", "lease", "handoff"} {
			if (operation == "read-update" || operation == "stage-outbox") && expiry != "lease" {
				continue
			}
			t.Run(operation+"/"+expiry, func(t *testing.T) {
				h := newHandoffFixture(t)
				metrics := observability.New()
				if err := h.database.ConfigureFileMetrics(metrics); err != nil {
					t.Fatal(err)
				}
				var offer *files.FileOffer
				if operation != "offer" {
					offer = h.offer(t)
				}
				if operation == "stage" || operation == "stage-outbox" {
					if _, err := h.repository.RedeemFileRead(h.ctx, offer.HandoffID, offer.DownloadToken, fileTestPolicy, func(files.ReadPermit) error { return nil }); err != nil {
						t.Fatal(err)
					}
				}
				h.exec(t, `create table handoff_deadline_fixture(deadline timestamptz not null)`)
				table, event, condition, fragment := "file_handoffs", "insert", "true", "insert into file_handoffs"
				prefix := ""
				switch operation {
				case "offer":
					if expiry == "lease" || expiry == "handoff" {
						prefix = `new.lease_until=least(new.lease_until,(select deadline from handoff_deadline_fixture));`
						if expiry == "handoff" {
							prefix += `new.expires_at=(select deadline from handoff_deadline_fixture);`
						}
					}
				case "renew":
					event, condition, fragment = "update", "true", "update file_handoffs set lease_until"
				case "read-update":
					event, condition, fragment = "update", "new.state='downloading' and old.state='offered'", "update file_handoffs set state='downloading'"
				case "read":
					table, condition, fragment = "audit_log", "new.action='file.host_read'", "insert into audit_log"
				case "stage":
					table, condition, fragment = "audit_log", "new.action='file.host_staged'", "insert into audit_log"
				case "stage-outbox":
					table, event, condition, fragment = "control_outbox", "update", "new.topic='file.clean' and new.published_at is not null", "update control_outbox set published_at"
				}
				h.exec(t, `create function hold_handoff_deadline() returns trigger language plpgsql as $$ begin `+prefix+`
				 if `+condition+` then perform pg_advisory_xact_lock(426966);end if;return new;end $$;
				 create trigger hold_handoff_deadline before `+event+` on `+table+` for each row execute function hold_handoff_deadline()`)
				var deadline time.Time
				if err := h.database.DB.QueryRowContext(h.ctx, `insert into handoff_deadline_fixture values(clock_timestamp()+interval '600 milliseconds') returning deadline`).Scan(&deadline); err != nil {
					t.Fatal(err)
				}
				want := files.ErrAccess
				switch expiry {
				case "credential":
					h.host.CredentialExpiresAt = deadline
					if offer != nil {
						h.exec(t, `update file_handoffs set credential_expires_at=$1,expires_at=least(expires_at,$1),lease_until=least(lease_until,$1)`, deadline)
					}
				case "file":
					h.exec(t, `update files set expires_at=$1 where id=$2`, deadline, h.file.ID)
				case "grant":
					h.exec(t, `update runtime_grants set expires_at=$1`, deadline)
				case "lease":
					want = files.ErrStale
					if offer != nil {
						h.exec(t, `update file_handoffs set lease_until=$1`, deadline)
					}
				case "handoff":
					want = files.ErrStale
					if offer != nil {
						h.exec(t, `update file_handoffs set expires_at=$1,lease_until=least(lease_until,$1)`, deadline)
					}
				}
				var before string
				if err := h.database.DB.QueryRowContext(h.ctx, `select coalesce(jsonb_agg(to_jsonb(h) order by id),'[]')::text from file_handoffs h`).Scan(&before); err != nil {
					t.Fatal(err)
				}
				gate, err := h.database.DB.BeginTx(h.ctx, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer gate.Rollback()
				if _, err := gate.ExecContext(h.ctx, `select pg_advisory_xact_lock(426966)`); err != nil {
					t.Fatal(err)
				}
				result := make(chan error, 1)
				go func() {
					var err error
					switch operation {
					case "offer":
						var current *files.FileOffer
						current, err = h.repository.IssueHandoff(h.ctx, h.host, h.file.ID, fileTestPolicy)
						if err != nil && current != nil {
							result <- errors.New("denied offer exposed its secret")
							return
						}
					case "renew":
						_, err = h.repository.RenewHandoff(h.ctx, h.host, offer.HandoffID, fileTestPolicy)
					case "read", "read-update":
						var permit files.ReadPermit
						permit, err = h.repository.RedeemFileRead(h.ctx, offer.HandoffID, offer.DownloadToken, fileTestPolicy, func(files.ReadPermit) error { return nil })
						if err != nil && permit.Handoff.ID != "" {
							result <- errors.New("denied read returned a permit")
							return
						}
					default:
						err = h.repository.StageHandoff(h.ctx, h.host, offer.HandoffID, h.file.SHA256, h.file.SizeBytes, "normalized.txt", fileTestPolicy)
					}
					result <- err
				}()
				waitForGrantLock(t, h.ctx, h.database, fragment)
				waitForGrantDatabaseExpiry(t, h.ctx, h.database, deadline)
				if err := gate.Commit(); err != nil {
					t.Fatal(err)
				}
				if err := <-result; !errors.Is(err, want) {
					t.Fatal("expired handoff authority survived its database wait", err)
				}
				var after string
				if err := h.database.DB.QueryRowContext(h.ctx, `select coalesce(jsonb_agg(to_jsonb(h) order by id),'[]')::text from file_handoffs h`).Scan(&after); err != nil {
					t.Fatal(err)
				}
				if before != after {
					t.Fatal("expired admission changed handoff state or lifetime")
				}
				var reads, stages, published int
				if err := h.database.DB.QueryRowContext(h.ctx, `select
				 (select count(*) from audit_log where action='file.host_read'),
				 (select count(*) from audit_log where action='file.host_staged'),
				 (select count(*) from control_outbox where topic='file.clean' and published_at is not null)`).Scan(&reads, &stages, &published); err != nil {
					t.Fatal(err)
				}
				wantReads, wantOffers := 0, 1
				if operation == "stage" || operation == "stage-outbox" {
					wantReads = 1
				}
				if operation == "offer" {
					wantOffers = 0
				}
				if reads != wantReads || stages != 0 || published != 0 {
					t.Fatal("failed handoff admission left success facts", reads, stages, published)
				}
				if handoffEventCount(t, metrics, "offered") != float64(wantOffers) || handoffEventCount(t, metrics, "read_started") != float64(wantReads) || handoffEventCount(t, metrics, "staged") != 0 {
					t.Fatal("failed handoff admission emitted a success milestone")
				}
				if operation == "renew" && expiry == "lease" {
					// Cleanup is a negative operation and must still work after
					// expiry. A new offer gets a new one-use capability.
					if err := h.repository.EndHandoff(h.ctx, h.host, offer.HandoffID); err != nil {
						t.Fatal("expired handoff could not be retired", err)
					}
					fresh := h.offer(t)
					if fresh.HandoffID == offer.HandoffID || fresh.DownloadToken == offer.DownloadToken {
						t.Fatal("expired renewal reused its old capability")
					}
					verify := func(files.ReadPermit) error { return nil }
					if _, err := h.repository.RedeemFileRead(h.ctx, fresh.HandoffID, fresh.DownloadToken, fileTestPolicy, verify); err != nil {
						t.Fatal("fresh handoff could not proceed after rollback", err)
					}
					if _, err := h.repository.RedeemFileRead(h.ctx, fresh.HandoffID, fresh.DownloadToken, fileTestPolicy, verify); !errors.Is(err, files.ErrAccess) {
						t.Fatal("fresh download capability lost one-use semantics", err)
					}
				}
			})
		}
	}
}

func TestFileHandoffIgnoredOfferOrRenewalCannotReturnAuthority(t *testing.T) {
	for _, operation := range []string{"offer", "renew"} {
		t.Run(operation, func(t *testing.T) {
			h := newHandoffFixture(t)
			metrics := observability.New()
			if err := h.database.ConfigureFileMetrics(metrics); err != nil {
				t.Fatal(err)
			}
			event := "insert"
			var offer *files.FileOffer
			if operation == "renew" {
				offer = h.offer(t)
				event = "update"
			}
			h.exec(t, `create function ignore_handoff_write() returns trigger language plpgsql as $$ begin return null;end $$;
			 create trigger ignore_handoff_write before `+event+` on file_handoffs for each row execute function ignore_handoff_write()`)
			if operation == "offer" {
				if current, err := h.repository.IssueHandoff(h.ctx, h.host, h.file.ID, fileTestPolicy); current != nil || !errors.Is(err, files.ErrUnavailable) {
					t.Fatal("ignored insert returned a download secret", err)
				}
				if handoffEventCount(t, metrics, "offered") != 0 {
					t.Fatal("ignored offer counted a success milestone")
				}
			} else {
				if _, err := h.repository.RenewHandoff(h.ctx, h.host, offer.HandoffID, fileTestPolicy); !errors.Is(err, files.ErrUnavailable) {
					t.Fatal("ignored update returned renewed authority", err)
				}
			}
			h.exec(t, `drop trigger ignore_handoff_write on file_handoffs;drop function ignore_handoff_write()`)
			if operation == "offer" {
				h.offer(t)
			} else if _, err := h.repository.RenewHandoff(h.ctx, h.host, offer.HandoffID, fileTestPolicy); err != nil {
				t.Fatal("live authority did not recover after failed write", err)
			}
		})
	}
}
