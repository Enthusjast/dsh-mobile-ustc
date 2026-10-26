package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestKnownSessionTargetDoesNotGrantDirectoryEnumeration(t *testing.T) {
	h := questionFixture(t)
	if _, err := h.database.DB.ExecContext(h.ctx, `update runtime_grants set role='operator'`); err != nil {
		t.Fatal(err)
	}
	identity := UserIdentity{Issuer: h.principal.Issuer, Subject: h.principal.Subject}
	read := func(runtime, session, proof string) (SessionTarget, error) {
		return h.database.SessionReadTarget(h.ctx, identity, h.ticket.DeviceID, proof, runtime, session, time.Now().Add(time.Minute))
	}
	target, err := read(h.connection.RuntimeID, h.request.SessionID, h.ticket.ProofKeyThumbprint)
	if err != nil || target.Runtime.ID != h.connection.RuntimeID || target.Session.ID != h.request.SessionID || target.Runtime.Access == nil || target.Runtime.Access.Role != "operator" || target.Runtime.Access.GrantVersion != h.ticket.GrantVersion {
		t.Fatal("known resource lookup failed", err, target)
	}
	for name, count := range map[string]int{"hosts": func() int {
		rows, e := h.database.ListHosts(h.ctx, identity)
		if e != nil {
			t.Fatal(e)
		}
		return len(rows)
	}(),
		"runtimes": func() int {
			rows, e := h.database.ListRuntimes(h.ctx, identity)
			if e != nil {
				t.Fatal(e)
			}
			return len(rows)
		}(),
		"sessions": func() int {
			rows, e := h.database.ListSessions(h.ctx, identity, h.connection.RuntimeID)
			if e != nil {
				t.Fatal(e)
			}
			return len(rows)
		}()} {
		if count != 0 {
			t.Fatal("known target widened enumeration", name)
		}
	}
	encoded, _ := json.Marshal(target)
	if strings.Contains(string(encoded), h.request.DSHSessionID) || strings.Contains(string(encoded), "workspace_ref") || strings.Contains(string(encoded), "alias") {
		t.Fatal("known target exposed private or directory-only metadata")
	}
	if _, err := h.database.DB.ExecContext(h.ctx, `update sessions set state='unavailable' where id=$1`, h.request.SessionID); err != nil {
		t.Fatal(err)
	}
	if target, err = read(h.connection.RuntimeID, h.request.SessionID, h.ticket.ProofKeyThumbprint); err != nil || target.Session.State != "unavailable" {
		t.Fatal("offline metadata was fabricated", err)
	}
	for _, x := range []struct{ runtime, session, proof string }{{h.connection.RuntimeID, h.request.SessionID, "wrong-key"}, {h.connection.RuntimeID, approvalTestUUID(t), h.ticket.ProofKeyThumbprint}, {approvalTestUUID(t), h.request.SessionID, h.ticket.ProofKeyThumbprint}} {
		if _, err = read(x.runtime, x.session, x.proof); !errors.Is(err, ErrAccessDenied) {
			t.Fatal("wrong resource or key read metadata", err)
		}
	}
	if _, err = h.database.SessionReadTarget(h.ctx, identity, h.ticket.DeviceID, h.ticket.ProofKeyThumbprint, h.connection.RuntimeID, h.request.SessionID, time.Now().Add(-time.Second)); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("expired credential read metadata", err)
	}
	if _, err = h.database.DB.ExecContext(h.ctx, `update runtime_grants set scope=jsonb_set(scope,'{actions}','["session.list"]')`); err != nil {
		t.Fatal(err)
	}
	if _, err = read(h.connection.RuntimeID, h.request.SessionID, h.ticket.ProofKeyThumbprint); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("list-only scope read a known target", err)
	}
}

func TestQuestionAnswerStatusCannotReplaceGeneralStatusOrClassifyLegacyRows(t *testing.T) {
	h := questionFixture(t)
	identity := UserIdentity{Issuer: h.principal.Issuer, Subject: h.principal.Subject}
	if _, err := h.database.DB.ExecContext(h.ctx, `update runtime_grants set role='operator'`); err != nil {
		t.Fatal(err)
	}
	id := approvalTestUUID(t)
	digest := strings.Repeat("a", 64)
	if _, err := h.database.RecordRealtimeCommand(h.ctx, h.ticket, "question.answer", id, h.request.SessionID, digest); err != nil {
		t.Fatal(err)
	}
	read := func(request string) (CommandStatus, error) {
		return h.database.QuestionAnswerStatus(h.ctx, identity, h.ticket.DeviceID, h.ticket.ProofKeyThumbprint, h.connection.RuntimeID, h.request.SessionID, request, time.Now().Add(time.Minute))
	}
	status, err := read(id)
	if err != nil || status.RequestID != id || status.PayloadSHA256 != digest || status.State != "received" {
		t.Fatal("own typed answer was not reconciled", err, status)
	}
	if _, err = h.database.CommandStatus(h.ctx, identity, h.ticket.DeviceID, id); err == nil {
		t.Fatal("question permission granted generic command.status")
	}
	if _, err = h.database.DB.ExecContext(h.ctx, `update runtime_grants set scope=jsonb_set(scope,'{actions}','["session.read","question.answer","message.submit"]')`); err != nil {
		t.Fatal(err)
	}
	otherKind := h.ticket
	otherKind.Scope.Actions = []string{"session.read", "question.answer", "message.submit"}
	if _, err = h.database.RecordRealtimeCommand(h.ctx, otherKind, "message.submit", id, h.request.SessionID, digest); !errors.Is(err, ErrCommandConflict) {
		t.Fatal("same digest and ID changed its classified action", err)
	}
	if _, err = h.database.DB.ExecContext(h.ctx, `update runtime_grants set scope=jsonb_set(scope,'{actions}','["session.read","question.answer"]')`); err != nil {
		t.Fatal(err)
	}
	for _, action := range []*string{ptr("message.submit"), nil} {
		other := approvalTestUUID(t)
		_, err = h.database.DB.ExecContext(h.ctx, `insert into commands(device_id,request_id,user_id,runtime_id,session_id,payload_sha256,state,action) values($1,$2,$3,$4,$5,$6,'received',$7)`, h.ticket.DeviceID, other, h.ticket.UserID, h.connection.RuntimeID, h.request.SessionID, digest, action)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = read(other); !errors.Is(err, ErrAccessDenied) {
			t.Fatal("another action or unclassified record was exposed", err)
		}
		if action == nil {
			if _, err = h.database.RecordRealtimeCommand(h.ctx, h.ticket, "question.answer", other, h.request.SessionID, digest); err != nil {
				t.Fatal("legacy exact retry failed", err)
			}
			if _, err = read(other); !errors.Is(err, ErrAccessDenied) {
				t.Fatal("retry guessed a legacy action", err)
			}
		}
	}
	for _, change := range []struct{ device, proof, runtime, session, request string }{{h.ticket.DeviceID, "wrong-key", h.connection.RuntimeID, h.request.SessionID, id}, {h.ticket.DeviceID, h.ticket.ProofKeyThumbprint, h.connection.RuntimeID, approvalTestUUID(t), id}, {h.ticket.DeviceID, h.ticket.ProofKeyThumbprint, approvalTestUUID(t), h.request.SessionID, id}} {
		if _, err = h.database.QuestionAnswerStatus(h.ctx, identity, change.device, change.proof, change.runtime, change.session, change.request, time.Now().Add(time.Minute)); !errors.Is(err, ErrAccessDenied) {
			t.Fatal("answer query crossed key or resource", err)
		}
	}
	if _, err = h.database.DB.ExecContext(h.ctx, `update runtime_grants set scope=jsonb_set(scope,'{actions}','["session.read"]')`); err != nil {
		t.Fatal(err)
	}
	if _, err = read(id); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("revoked question authority still read answer status", err)
	}
}

func TestCommandActionMigrationRollbackPreservesStatusWithoutReclassifyingIt(t *testing.T) {
	h := questionFixture(t)
	id := approvalTestUUID(t)
	digest := strings.Repeat("b", 64)
	if _, err := h.database.RecordRealtimeCommand(h.ctx, h.ticket, "question.answer", id, h.request.SessionID, digest); err != nil {
		t.Fatal(err)
	}
	_, source, _, _ := runtime.Caller(0)
	for _, direction := range []string{"down", "up"} {
		body, err := os.ReadFile(filepath.Join(filepath.Dir(source), "../../../../deploy/sql/016_command_actions."+direction+".sql"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = h.database.DB.ExecContext(h.ctx, string(body)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.database.DB.ExecContext(h.ctx, `update runtime_grants set scope=jsonb_set(scope,'{actions}','["session.read","question.answer","command.status"]')`); err != nil {
		t.Fatal(err)
	}
	identity := UserIdentity{Issuer: h.principal.Issuer, Subject: h.principal.Subject}
	status, err := h.database.CommandStatus(h.ctx, identity, h.ticket.DeviceID, id)
	if err != nil || status.RequestID != id || status.SessionID != h.request.SessionID || status.PayloadSHA256 != digest || status.State != "received" {
		t.Fatal("migration lost original command facts", err, status)
	}
	if _, err = h.database.RecordRealtimeCommand(h.ctx, h.ticket, "question.answer", id, h.request.SessionID, digest); err != nil {
		t.Fatal("migration broke exact retry", err)
	}
	if _, err = h.database.QuestionAnswerStatus(h.ctx, identity, h.ticket.DeviceID, h.ticket.ProofKeyThumbprint, h.connection.RuntimeID, h.request.SessionID, id, time.Now().Add(time.Minute)); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("migration or retry guessed an erased action", err)
	}
}
