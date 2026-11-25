package pgdump

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prisandikevin12/pgvault/internal/crypto"
	"github.com/prisandikevin12/pgvault/internal/storage"
)

func TestParseMajorVersion(t *testing.T) {
	cases := []struct {
		input   string
		want    int
		wantErr bool
	}{
		{input: "160004", want: 16},
		{input: "150008", want: 15},
		{input: "180006", want: 18},
		{input: "100000", want: 10},
		{input: " 140012\n", want: 14},
		{input: "90624", want: 9},
		{input: "", wantErr: true},
		{input: "not-a-number", wantErr: true},
		{input: "0", wantErr: true},
		{input: "-160000", wantErr: true},
		{input: "999", wantErr: true},
	}

	for _, tc := range cases {
		got, err := ParseMajorVersion(tc.input)
		if (err != nil) != tc.wantErr {
			t.Errorf("ParseMajorVersion(%q) error = %v, wantErr = %v", tc.input, err, tc.wantErr)
			continue
		}
		if !tc.wantErr && got != tc.want {
			t.Errorf("ParseMajorVersion(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

func TestTailBuffer(t *testing.T) {
	tb := newTailBuffer(8)

	_, _ = tb.Write([]byte("abcd"))
	if got := tb.String(); got != "abcd" {
		t.Fatalf("got %q, want %q", got, "abcd")
	}

	_, _ = tb.Write([]byte("efgh"))
	if got := tb.String(); got != "abcdefgh" {
		t.Fatalf("got %q, want %q", got, "abcdefgh")
	}

	_, _ = tb.Write([]byte("123"))
	if got := tb.String(); got != "defgh123" {
		t.Fatalf("got %q, want %q", got, "defgh123")
	}

	// Single write larger than limit keeps only the last `limit` bytes.
	_, _ = tb.Write([]byte("0123456789ABCDEF"))
	if got := tb.String(); got != "89ABCDEF" {
		t.Fatalf("got %q, want %q", got, "89ABCDEF")
	}
}

type fakeUploader struct {
	mu       sync.Mutex
	data     []byte
	key      string
	uploadFn func(ctx context.Context, key string, r io.Reader, contentType string) (storage.UploadResult, error)
}

func (f *fakeUploader) UploadStream(ctx context.Context, key string, r io.Reader, contentType string) (storage.UploadResult, error) {
	if f.uploadFn != nil {
		return f.uploadFn(ctx, key, r, contentType)
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return storage.UploadResult{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.key = key
	f.data = b
	return storage.UploadResult{Bucket: "test-bucket", Key: key}, nil
}

func TestValidateBackupRequest(t *testing.T) {
	validKEK, _ := crypto.GenerateDEK()
	uploader := &fakeUploader{}

	cases := []struct {
		name    string
		req     BackupRequest
		wantErr bool
	}{
		{
			name: "valid",
			req: BackupRequest{
				DSN:       "postgres://user:pass@localhost:5432/db",
				Storage:   uploader,
				ObjectKey: "backups/db-1.pgv",
				KEK:       validKEK,
			},
			wantErr: false,
		},
		{
			name: "missing_dsn",
			req: BackupRequest{
				Storage:   uploader,
				ObjectKey: "backups/db-1.pgv",
				KEK:       validKEK,
			},
			wantErr: true,
		},
		{
			name: "nil_storage",
			req: BackupRequest{
				DSN:       "postgres://user:pass@localhost:5432/db",
				ObjectKey: "backups/db-1.pgv",
				KEK:       validKEK,
			},
			wantErr: true,
		},
		{
			name: "missing_object_key",
			req: BackupRequest{
				DSN:     "postgres://user:pass@localhost:5432/db",
				Storage: uploader,
				KEK:     validKEK,
			},
			wantErr: true,
		},
		{
			name: "invalid_kek_length",
			req: BackupRequest{
				DSN:       "postgres://user:pass@localhost:5432/db",
				Storage:   uploader,
				ObjectKey: "backups/db-1.pgv",
				KEK:       make([]byte, 16),
			},
			wantErr: true,
		},
		{
			name: "negative_chunk_size",
			req: BackupRequest{
				DSN:       "postgres://user:pass@localhost:5432/db",
				Storage:   uploader,
				ObjectKey: "backups/db-1.pgv",
				KEK:       validKEK,
				ChunkSize: -1,
			},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateBackupRequest(tc.req)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateBackupRequest() error = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestRunEncryptedBackup_ValidationFailure(t *testing.T) {
	if _, err := RunEncryptedBackup(context.Background(), BackupRequest{}); err == nil {
		t.Fatalf("RunEncryptedBackup() with empty request succeeded, want error")
	}
}

func TestStreamingPipeline_Success(t *testing.T) {
	kek, _ := crypto.GenerateDEK()
	dek, _ := crypto.GenerateDEK()
	uploader := &fakeUploader{}

	plaintext := bytes.Repeat([]byte("PGDMP_SYNTHETIC_BACKUP_DATA_1234567890"), 5000)

	stats, err := streamDumpEncryptUpload(
		context.Background(),
		uploader,
		"backups/test.pgv",
		dek,
		1024,
		func(ctx context.Context, w io.Writer) error {
			_, err := w.Write(plaintext)
			return err
		},
	)
	if err != nil {
		t.Fatalf("streamDumpEncryptUpload() error: %v", err)
	}

	if stats.PlaintextBytes != int64(len(plaintext)) {
		t.Errorf("PlaintextBytes = %d, want %d", stats.PlaintextBytes, len(plaintext))
	}
	if stats.CiphertextBytes != int64(len(uploader.data)) {
		t.Errorf("CiphertextBytes = %d, want %d", stats.CiphertextBytes, len(uploader.data))
	}
	if bytes.Contains(uploader.data, []byte("PGDMP_SYNTHETIC_BACKUP_DATA")) {
		t.Fatalf("uploaded ciphertext contains plaintext sentinel")
	}

	// Wrap/unwrap sanity + decrypt stream
	wrapped, err := crypto.WrapDEK(kek, dek)
	if err != nil {
		t.Fatalf("WrapDEK() error: %v", err)
	}
	unwrapped, err := crypto.UnwrapDEK(kek, wrapped)
	if err != nil {
		t.Fatalf("UnwrapDEK() error: %v", err)
	}

	var decrypted bytes.Buffer
	if err := crypto.DecryptStream(bytes.NewReader(uploader.data), &decrypted, unwrapped); err != nil {
		t.Fatalf("DecryptStream() error: %v", err)
	}
	if !bytes.Equal(decrypted.Bytes(), plaintext) {
		t.Fatalf("decrypted output mismatch")
	}
}

func TestStreamingPipeline_DumpErrorAbortsUpload(t *testing.T) {
	dek, _ := crypto.GenerateDEK()
	dumpErr := errors.New("pg_dump exited 1: connection refused")

	uploadSawErr := false
	uploader := &fakeUploader{
		uploadFn: func(ctx context.Context, key string, r io.Reader, contentType string) (storage.UploadResult, error) {
			_, err := io.ReadAll(r)
			if err != nil {
				uploadSawErr = true
				return storage.UploadResult{}, err
			}
			return storage.UploadResult{Key: key}, nil
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := streamDumpEncryptUpload(
		ctx,
		uploader,
		"backups/fail-dump.pgv",
		dek,
		1024,
		func(ctx context.Context, w io.Writer) error {
			_, _ = w.Write([]byte("partial dump bytes before crash"))
			return dumpErr
		},
	)
	if err == nil {
		t.Fatalf("expected error when dump fails, got nil")
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("error = %q, expected to contain dump error", err.Error())
	}
	if !uploadSawErr {
		t.Fatalf("UploadStream saw clean EOF instead of error when dump failed")
	}
}

func TestStreamingPipeline_UploadErrorStopsDumpWithoutDeadlock(t *testing.T) {
	dek, _ := crypto.GenerateDEK()
	uploadErr := errors.New("s3 503 slow down")

	uploader := &fakeUploader{
		uploadFn: func(ctx context.Context, key string, r io.Reader, contentType string) (storage.UploadResult, error) {
			buf := make([]byte, 32)
			_, _ = r.Read(buf)
			return storage.UploadResult{}, uploadErr
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := streamDumpEncryptUpload(
		ctx,
		uploader,
		"backups/fail-upload.pgv",
		dek,
		1024,
		func(ctx context.Context, w io.Writer) error {
			chunk := bytes.Repeat([]byte("A"), 4096)
			for {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
					if _, err := w.Write(chunk); err != nil {
						return err
					}
				}
			}
		},
	)
	if err == nil {
		t.Fatalf("expected error when upload fails, got nil")
	}
	if !errors.Is(err, uploadErr) {
		t.Errorf("error = %v, want wrapped %v", err, uploadErr)
	}
}

func TestSplitDSNPassword(t *testing.T) {
	cases := []struct {
		name         string
		dsn          string
		wantPassword string
		mustContain  []string
		mustNotHave  []string
	}{
		{
			name:         "uri_with_password_and_sslmode",
			dsn:          "postgres://backup_user:SuperSecret123@db.prod.example.com:5432/appdb?sslmode=require&connect_timeout=5",
			wantPassword: "SuperSecret123",
			mustContain:  []string{"postgres://backup_user@db.prod.example.com:5432/appdb", "sslmode=require", "connect_timeout=5"},
			mustNotHave:  []string{"SuperSecret123"},
		},
		{
			name:         "uri_without_password",
			dsn:          "postgresql://readonly@10.0.1.5:5432/mydb?sslmode=disable",
			wantPassword: "",
			mustContain:  []string{"postgresql://readonly@10.0.1.5:5432/mydb", "sslmode=disable"},
		},
		{
			name:         "kv_unquoted_password",
			dsn:          "host=db.internal port=5432 user=pgvault password=kvSecretPass dbname=prod sslmode=verify-full",
			wantPassword: "kvSecretPass",
			mustContain:  []string{"host=db.internal", "port=5432", "user=pgvault", "dbname=prod", "sslmode=verify-full"},
			mustNotHave:  []string{"kvSecretPass", "password="},
		},
		{
			name:         "kv_quoted_password_with_spaces",
			dsn:          "host=db.internal user=pgvault password='my secret pass' dbname=prod sslmode=require",
			wantPassword: "my secret pass",
			mustContain:  []string{"host=db.internal", "user=pgvault", "dbname=prod", "sslmode=require"},
			mustNotHave:  []string{"my secret pass", "password="},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			safeDSN, pw, err := splitDSNPassword(tc.dsn)
			if err != nil {
				t.Fatalf("splitDSNPassword() unexpected error: %v", err)
			}
			if pw != tc.wantPassword {
				t.Errorf("password = %q, want %q", pw, tc.wantPassword)
			}
			for _, sub := range tc.mustContain {
				if !strings.Contains(safeDSN, sub) {
					t.Errorf("safeDSN %q missing %q", safeDSN, sub)
				}
			}
			for _, forbidden := range tc.mustNotHave {
				if strings.Contains(safeDSN, forbidden) {
					t.Errorf("safeDSN %q leaked forbidden substring %q", safeDSN, forbidden)
				}
			}
		})
	}
}

func TestSanitizePGDumpError_RedactsSecrets(t *testing.T) {
	raw := "pg_dump: error: connection to server at postgres://admin:TopSecret99@db.local:5432/prod failed (password=TopSecret99)"
	cleaned := sanitizePGDumpError(raw, "TopSecret99")
	if strings.Contains(cleaned, "TopSecret99") {
		t.Fatalf("sanitizePGDumpError leaked password: %q", cleaned)
	}
}
