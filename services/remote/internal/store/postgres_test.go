package store

import (
	"errors"
	"strings"
	"testing"
)

func TestPostgresDSNRequiresFullTLSVerificationForRemoteHosts(t *testing.T) {
	tests := []struct {
		name string
		dsn  string
		want error
	}{
		{name: "loopback development", dsn: "postgres://remote:secret@127.0.0.1:5432/remote?sslmode=disable"},
		{name: "local hostname development", dsn: "postgres://remote:secret@localhost:5432/remote?sslmode=disable"},
		{name: "unix socket development", dsn: "postgres://remote:secret@/remote?host=/var/run/postgresql&sslmode=disable"},
		{name: "remote verified TLS", dsn: "postgres://remote:secret@db.example.edu:5432/remote?sslmode=verify-full&sslrootcert=/etc/ssl/certs/ca-certificates.crt"},
		{name: "remote default prefer refused", dsn: "postgres://remote:secret@db.example.edu:5432/remote", want: ErrDatabaseConfig},
		{name: "remote require without verification refused", dsn: "postgres://remote:secret@db.example.edu:5432/remote?sslmode=require", want: ErrDatabaseConfig},
		{name: "remote verify-ca without hostname validation refused", dsn: "postgres://remote:secret@db.example.edu:5432/remote?sslmode=verify-ca", want: ErrDatabaseConfig},
		{name: "empty refused", dsn: " ", want: ErrDatabaseConfig},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateDSN(test.dsn)
			if test.want == nil && err != nil {
				t.Fatalf("valid DSN was refused: %v", err)
			}
			if test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("ValidateDSN() error = %v, want %v", err, test.want)
			}
			if err != nil && strings.Contains(err.Error(), "secret") {
				t.Fatal("DSN password leaked in error")
			}
		})
	}
}
