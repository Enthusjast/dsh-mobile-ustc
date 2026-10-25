package store

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"dsh-mobile-ustc/services/remote/internal/files"
)

func TestPostgresFileMigrationRollbackCannotReviveUnboundCleanRows(t *testing.T) {
	h := newFileFixture(t)
	file := h.scanning(t)
	claim := h.claim(t)
	if err := h.repository.CompleteScan(h.ctx, claim); err != nil {
		t.Fatal(err)
	}
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("migration source unavailable")
	}
	directory := filepath.Join(filepath.Dir(source), "../../../../deploy/sql")
	scope, err := os.ReadFile(filepath.Join(directory, "013_export_scope.down.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.database.DB.ExecContext(h.ctx, string(scope)); err != nil {
		t.Fatal(err)
	}
	exports, err := os.ReadFile(filepath.Join(directory, "012_file_exports.down.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.database.DB.ExecContext(h.ctx, string(exports)); err != nil {
		t.Fatal(err)
	}
	newest, err := os.ReadFile(filepath.Join(directory, "011_file_message_refs.down.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.database.DB.ExecContext(h.ctx, string(newest)); err != nil {
		t.Fatal(err)
	}
	dependent, err := os.ReadFile(filepath.Join(directory, "010_file_handoffs.down.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.database.DB.ExecContext(h.ctx, string(dependent)); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"009_file_transfers.down.sql", "009_file_transfers.up.sql"} {
		body, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.database.DB.ExecContext(h.ctx, string(body)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var state string
		if err := h.database.DB.QueryRowContext(h.ctx, `select state from files where id=$1`, file.ID).Scan(&state); err != nil || state != "expired" {
			t.Fatalf("rollback restored state=%s error=%v", state, err)
		}
	}
	dependent, err = os.ReadFile(filepath.Join(directory, "010_file_handoffs.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.database.DB.ExecContext(h.ctx, string(dependent)); err != nil {
		t.Fatal(err)
	}
	newest, err = os.ReadFile(filepath.Join(directory, "011_file_message_refs.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.database.DB.ExecContext(h.ctx, string(newest)); err != nil {
		t.Fatal(err)
	}
	exports, err = os.ReadFile(filepath.Join(directory, "012_file_exports.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.database.DB.ExecContext(h.ctx, string(exports)); err != nil {
		t.Fatal(err)
	}
	scope, err = os.ReadFile(filepath.Join(directory, "013_export_scope.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.database.DB.ExecContext(h.ctx, string(scope)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.repository.Status(h.ctx, h.actor, file.ID); !errors.Is(err, files.ErrAccess) {
		t.Fatal("migration replay converted old metadata into current authority")
	}
}
