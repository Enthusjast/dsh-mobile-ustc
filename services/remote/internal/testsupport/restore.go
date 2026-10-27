package testsupport

import (
	"context"
	"database/sql"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// RestoredPostgresDatabase performs a real custom-format dump and restore into
// a separate, newly initialized socket-only cluster, with a distinct XID history.
// It accepts only the disposable runner's known password-free local cluster.
func RestoredPostgresDatabase(t *testing.T, source *sql.DB) (context.Context, *sql.DB, string) {
	t.Helper()
	root, dump := os.Getenv("REMOTE_TEST_CLUSTER_ROOT"), os.Getenv("REMOTE_TEST_PG_DUMP")
	if root == "" || dump == "" {
		t.Skip("explicit disposable backup/restore runner required")
	}
	config, err := pgx.ParseConfig(os.Getenv("REMOTE_TEST_DATABASE_URL"))
	if err != nil || config.Host != root || !filepath.IsAbs(root) || config.Password != "" || config.User != "dsh_e2e" {
		t.Fatal("restore fixture requires the runner's isolated local cluster")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	var databaseName string
	if err := source.QueryRowContext(ctx, `select current_database()`).Scan(&databaseName); err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp("", "dsh-restore-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	data, backup, log := filepath.Join(directory, "data"), filepath.Join(directory, "backup.dump"), filepath.Join(directory, "postgres.log")
	bin := filepath.Dir(dump)
	run := func(ctx context.Context, program string, args []string, environment []string) {
		t.Helper()
		command := exec.CommandContext(ctx, program, args...)
		command.Env = environment
		command.Stdout = io.Discard
		command.Stderr = io.Discard
		if err := command.Run(); err != nil {
			t.Fatalf("isolated restore step %s failed: %v", filepath.Base(program), err)
		}
	}
	environment := []string{"PATH=" + os.Getenv("PATH"), "PGHOST=" + root, "PGPORT=55439", "PGUSER=dsh_e2e", "PGDATABASE=" + databaseName, "PGSSLMODE=disable"}
	run(ctx, dump, []string{"--format=custom", "--no-owner", "--no-privileges", "--file", backup}, environment)
	if err := os.Chmod(backup, 0600); err != nil {
		t.Fatal(err)
	}
	run(ctx, filepath.Join(bin, "initdb"), []string{"-D", data, "--auth=trust", "--username=dsh_e2e", "--no-locale", "--encoding=UTF8"}, []string{"PATH=" + os.Getenv("PATH")})
	run(ctx, filepath.Join(bin, "pg_ctl"), []string{"-D", data, "-l", log, "-o", "-h '' -k " + directory + " -p 55441", "-w", "start"}, []string{"PATH=" + os.Getenv("PATH")})
	var restored *sql.DB
	t.Cleanup(func() {
		if restored != nil {
			_ = restored.Close()
		}
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		command := exec.CommandContext(cleanup, filepath.Join(bin, "pg_ctl"), "-D", data, "-m", "immediate", "-w", "stop")
		command.Stdout = io.Discard
		command.Stderr = io.Discard
		if err := command.Run(); err != nil {
			t.Error("owned restore cluster did not stop", err)
		}
	})
	environment = []string{"PATH=" + os.Getenv("PATH"), "PGHOST=" + directory, "PGPORT=55441", "PGUSER=dsh_e2e", "PGDATABASE=postgres", "PGSSLMODE=disable"}
	run(ctx, filepath.Join(bin, "pg_restore"), []string{"--exit-on-error", "--no-owner", "--no-privileges", "--dbname=postgres", backup}, environment)
	dsn := "host=" + directory + " port=55441 user=dsh_e2e dbname=postgres sslmode=disable"
	restoredConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	restored = stdlib.OpenDB(*restoredConfig)
	restored.SetMaxOpenConns(4)
	if err := restored.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	var originalID, restoredID string
	if err := source.QueryRowContext(ctx, `select system_identifier::text from pg_control_system()`).Scan(&originalID); err != nil {
		t.Fatal(err)
	}
	if err := restored.QueryRowContext(ctx, `select system_identifier::text from pg_control_system()`).Scan(&restoredID); err != nil || strings.TrimSpace(restoredID) == originalID {
		t.Fatal("restore reused source cluster history", err)
	}
	return ctx, restored, dsn
}
