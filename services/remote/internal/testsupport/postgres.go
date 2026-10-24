// Package testsupport creates isolated databases only in the explicitly configured test cluster.
package testsupport

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func PostgresDatabase(t *testing.T) (context.Context, *sql.DB) {
	t.Helper()
	dsn := os.Getenv("REMOTE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set REMOTE_TEST_DATABASE_URL to a local PostgreSQL admin DSN to run integration coverage")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)

	adminConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse test PostgreSQL DSN: %v", err)
	}
	adminConfig.Database = "postgres"
	admin, err := pgx.ConnectConfig(ctx, adminConfig)
	if err != nil {
		t.Fatalf("connect to PostgreSQL admin database: %v", err)
	}
	var testDB *sql.DB
	var testDatabaseName string
	t.Cleanup(func() {
		if testDB != nil {
			_ = testDB.Close()
		}
		if testDatabaseName != "" {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cleanupCancel()
			_, _ = admin.Exec(cleanupCtx, "drop database if exists "+testDatabaseName)
		}
		_ = admin.Close(context.Background())
	})

	randomName := make([]byte, 12)
	if _, err := rand.Read(randomName); err != nil {
		t.Fatal(err)
	}
	testDatabaseName = "dsh_remote_test_" + hex.EncodeToString(randomName)
	if _, err := admin.Exec(ctx, "create database "+testDatabaseName); err != nil {
		t.Fatalf("create isolated test database: %v", err)
	}

	testConfig := adminConfig.Copy()
	testConfig.Database = testDatabaseName
	migrationConnection, err := pgx.ConnectConfig(ctx, testConfig)
	if err != nil {
		t.Fatalf("connect to isolated test database: %v", err)
	}
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve integration test source path")
	}
	migrations, err := filepath.Glob(filepath.Join(filepath.Dir(sourceFile), "../../../../deploy/sql/*.up.sql"))
	if err != nil || len(migrations) == 0 {
		t.Fatal("resolve integration migrations")
	}
	for _, migrationPath := range migrations {
		name := filepath.Base(migrationPath)
		migration, err := os.ReadFile(migrationPath)
		if err != nil {
			_ = migrationConnection.Close(context.Background())
			t.Fatalf("read PostgreSQL migration %s: %v", name, err)
		}
		if _, err := migrationConnection.Exec(ctx, string(migration), pgx.QueryExecModeSimpleProtocol); err != nil {
			_ = migrationConnection.Close(context.Background())
			t.Fatalf("apply PostgreSQL migration %s: %v", name, err)
		}
	}
	if err := migrationConnection.Close(context.Background()); err != nil {
		t.Fatalf("close migration connection: %v", err)
	}

	testDB = stdlib.OpenDB(*testConfig)
	testDB.SetMaxOpenConns(4)
	if err := testDB.PingContext(ctx); err != nil {
		t.Fatalf("ping isolated test database: %v", err)
	}
	return ctx, testDB
}
