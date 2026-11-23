package verifier

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/prisandikevin12/pgvault/internal/crypto"
	"github.com/prisandikevin12/pgvault/internal/storage"
)

func TestValidateVerifyRequest(t *testing.T) {
	s3Client, err := storage.NewClient(context.Background(), storage.Config{
		EndpointURL:     "http://127.0.0.1:4566",
		Region:          "us-east-1",
		Bucket:          "pgvault-unit-test",
		AccessKeyID:     "test",
		SecretAccessKey: "test",
		ForcePathStyle:  true,
	})
	if err != nil {
		t.Fatalf("storage.NewClient() error: %v", err)
	}

	kek, _ := crypto.GenerateDEK()
	dek, _ := crypto.GenerateDEK()
	wrapped, _ := crypto.WrapDEK(kek, dek)

	cases := []struct {
		name    string
		req     VerifyRequest
		wantErr bool
	}{
		{
			name: "valid_minimal",
			req: VerifyRequest{
				Storage:    s3Client,
				ObjectKey:  "backups/app.pgv1",
				WrappedDEK: wrapped,
				KEK:        kek,
			},
			wantErr: false,
		},
		{
			name: "valid_with_sanity_query_and_version",
			req: VerifyRequest{
				Storage:        s3Client,
				ObjectKey:      "backups/app.pgv1",
				WrappedDEK:     wrapped,
				KEK:            kek,
				SanityQuery:    "SELECT count(*) FROM public.users",
				PGMajorVersion: 16,
				Timeout:        2 * time.Minute,
			},
			wantErr: false,
		},
		{
			name: "nil_storage",
			req: VerifyRequest{
				ObjectKey:  "backups/app.pgv1",
				WrappedDEK: wrapped,
				KEK:        kek,
			},
			wantErr: true,
		},
		{
			name: "empty_object_key",
			req: VerifyRequest{
				Storage:    s3Client,
				WrappedDEK: wrapped,
				KEK:        kek,
			},
			wantErr: true,
		},
		{
			name: "empty_wrapped_dek",
			req: VerifyRequest{
				Storage:   s3Client,
				ObjectKey: "backups/app.pgv1",
				KEK:       kek,
			},
			wantErr: true,
		},
		{
			name: "invalid_kek_length",
			req: VerifyRequest{
				Storage:    s3Client,
				ObjectKey:  "backups/app.pgv1",
				WrappedDEK: wrapped,
				KEK:        make([]byte, 16),
			},
			wantErr: true,
		},
		{
			name: "negative_pg_major_version",
			req: VerifyRequest{
				Storage:        s3Client,
				ObjectKey:      "backups/app.pgv1",
				WrappedDEK:     wrapped,
				KEK:            kek,
				PGMajorVersion: -1,
			},
			wantErr: true,
		},
		{
			name: "negative_timeout",
			req: VerifyRequest{
				Storage:    s3Client,
				ObjectKey:  "backups/app.pgv1",
				WrappedDEK: wrapped,
				KEK:        kek,
				Timeout:    -time.Second,
			},
			wantErr: true,
		},
		{
			name: "mutating_sanity_query_rejected",
			req: VerifyRequest{
				Storage:     s3Client,
				ObjectKey:   "backups/app.pgv1",
				WrappedDEK:  wrapped,
				KEK:         kek,
				SanityQuery: "DROP TABLE public.users",
			},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateVerifyRequest(tc.req)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateVerifyRequest() error = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestValidateSanityQuery(t *testing.T) {
	allowed := []string{
		"",
		"   ",
		"SELECT 1",
		"SELECT count(*) FROM public.customers;",
		"select count(*) from orders where status = 'deleted'",
		"SELECT count(*) FROM orders WHERE note = 'DROP TABLE is just text; INSERT'",
		"WITH active AS (SELECT id FROM customers WHERE active = true) SELECT count(*) FROM active",
		"/* count check */ SELECT count(*) FROM public.users -- trailing comment",
	}

	for _, q := range allowed {
		if err := ValidateSanityQuery(q); err != nil {
			t.Errorf("ValidateSanityQuery(%q) unexpected error: %v", q, err)
		}
	}

	rejected := []struct {
		name  string
		query string
	}{
		{"insert", "INSERT INTO users (name) VALUES ('x')"},
		{"update", "UPDATE users SET name = 'x'"},
		{"delete", "DELETE FROM users"},
		{"drop_table", "DROP TABLE users"},
		{"alter_table", "ALTER TABLE users ADD COLUMN x int"},
		{"create_table", "CREATE TABLE evil (id int)"},
		{"truncate", "TRUNCATE TABLE users"},
		{"grant", "GRANT ALL ON users TO public"},
		{"revoke", "REVOKE ALL ON users FROM public"},
		{"copy", "COPY users TO '/tmp/out'"},
		{"do_block", "DO $$ BEGIN PERFORM 1; END $$"},
		{"call_proc", "CALL some_proc()"},
		{"set_config_stmt", "SET statement_timeout = 0"},
		{"multi_statement", "SELECT 1; DROP TABLE users"},
		{"multi_select", "SELECT 1; SELECT 2"},
		{"cte_delete", "WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d"},
		{"cte_update", "WITH u AS (UPDATE users SET a = 1 RETURNING *) SELECT * FROM u"},
		{"select_into", "SELECT * INTO evil_copy FROM users"},
		{"select_for_update", "SELECT * FROM users FOR UPDATE"},
		{"set_config_func", "SELECT set_config('statement_timeout', '0', false)"},
		{"pg_read_file", "SELECT pg_read_file('/etc/passwd')"},
		{"pg_terminate", "SELECT pg_terminate_backend(1)"},
		{"dollar_quote", "SELECT $$hello$$"},
		{"unclosed_comment", "SELECT 1 /* unclosed"},
		{"psql_meta_command", "\\! id"},
	}

	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateSanityQuery(tc.query); err == nil {
				t.Errorf("ValidateSanityQuery(%q) succeeded, want error", tc.query)
			}
		})
	}
}

func TestRunVerification_UnwrapDEKFailure(t *testing.T) {
	s3Client, err := storage.NewClient(context.Background(), storage.Config{
		EndpointURL:     "http://127.0.0.1:4566",
		Region:          "us-east-1",
		Bucket:          "pgvault-unit-test",
		AccessKeyID:     "test",
		SecretAccessKey: "test",
		ForcePathStyle:  true,
	})
	if err != nil {
		t.Fatalf("storage.NewClient() error: %v", err)
	}

	kek1, _ := crypto.GenerateDEK()
	kek2, _ := crypto.GenerateDEK()
	dek, _ := crypto.GenerateDEK()
	wrapped, _ := crypto.WrapDEK(kek1, dek)

	res, err := RunVerification(context.Background(), VerifyRequest{
		Storage:    s3Client,
		ObjectKey:  "backups/app.pgv1",
		WrappedDEK: wrapped,
		KEK:        kek2, // wrong KEK -> unwrap must fail before Docker is touched
	})
	if err == nil {
		t.Fatalf("RunVerification() with wrong KEK succeeded, want error")
	}
	if res == nil {
		t.Fatalf("RunVerification() returned nil VerifyResult on failure")
	}
	if res.Passed {
		t.Errorf("VerifyResult.Passed = true, want false")
	}
	if !strings.Contains(strings.ToLower(res.Error), "unwrap") && !strings.Contains(strings.ToLower(res.Error), "decrypt") {
		t.Errorf("VerifyResult.Error = %q, expected unwrap/decrypt failure reason", res.Error)
	}
}

func TestMinPGMajorForArchiveHeader(t *testing.T) {
	cases := []struct {
		name   string
		header []byte
		want   int
	}{
		{"pg16_archive_1_15", []byte{'P', 'G', 'D', 'M', 'P', 1, 15, 0}, 16},
		{"pg17_18_archive_1_16", []byte{'P', 'G', 'D', 'M', 'P', 1, 16, 0}, 18},
		{"not_pgdmp", []byte("NOTPGDMP"), 0},
		{"too_short", []byte("PGD"), 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := minPGMajorForArchiveHeader(tc.header); got != tc.want {
				t.Errorf("minPGMajorForArchiveHeader(%x) = %d, want %d", tc.header, got, tc.want)
			}
		})
	}
}
