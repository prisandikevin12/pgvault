//go:build integration

package pgdump

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/prisandikevin12/pgvault/internal/crypto"
	"github.com/prisandikevin12/pgvault/internal/storage"
)

func testTargetDSN() string {
	if dsn := os.Getenv("PGVAULT_TEST_TARGET_DSN"); dsn != "" {
		return dsn
	}
	return "postgres://target_admin:target_dev_password@127.0.0.1:5433/customer_app?sslmode=disable"
}

func testS3Client(t *testing.T, ctx context.Context, bucket string) *storage.Client {
	t.Helper()
	endpoint := os.Getenv("PGVAULT_TEST_S3_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:4566"
	}
	region := os.Getenv("PGVAULT_TEST_S3_REGION")
	if region == "" {
		region = "us-east-1"
	}
	accessKey := os.Getenv("PGVAULT_TEST_S3_ACCESS_KEY")
	if accessKey == "" {
		accessKey = "test"
	}
	secretKey := os.Getenv("PGVAULT_TEST_S3_SECRET_KEY")
	if secretKey == "" {
		secretKey = "test"
	}

	client, err := storage.NewClient(ctx, storage.Config{
		EndpointURL:     endpoint,
		Region:          region,
		Bucket:          bucket,
		AccessKeyID:     accessKey,
		SecretAccessKey: secretKey,
		ForcePathStyle:  true,
	})
	if err != nil {
		t.Fatalf("storage.NewClient() error: %v", err)
	}
	if err := client.EnsureBucket(ctx); err != nil {
		t.Fatalf("EnsureBucket() error: %v", err)
	}
	return client
}

func TestPGDump_Integration_EncryptedBackupAndVerify(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	dsn := testTargetDSN()

	// 1. DetectMajorVersion against target-db (postgres:16-alpine)
	major, err := DetectMajorVersion(ctx, dsn)
	if err != nil {
		t.Fatalf("DetectMajorVersion() error: %v", err)
	}
	if major != 16 {
		t.Fatalf("DetectMajorVersion() = %d, want 16", major)
	}

	// 2. Seed a dummy table with distinctive plaintext values in target-db
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("pgx.Connect() error: %v", err)
	}
	defer conn.Close(context.Background())

	const (
		tableName = "pgvault_test_customers"
		sentinel  = "PGVAULT_SUPER_SECRET_PLAINTEXT_TOKEN_987654321"
	)

	t.Cleanup(func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanCancel()
		c, err := pgx.Connect(cleanCtx, dsn)
		if err == nil {
			_, _ = c.Exec(cleanCtx, "DROP TABLE IF EXISTS public."+tableName)
			_ = c.Close(cleanCtx)
		}
	})

	_, err = conn.Exec(ctx, fmt.Sprintf(`
		DROP TABLE IF EXISTS public.%s;
		CREATE TABLE public.%s (
			id SERIAL PRIMARY KEY,
			email TEXT NOT NULL,
			secret_note TEXT NOT NULL
		);
	`, tableName, tableName))
	if err != nil {
		t.Fatalf("create dummy table error: %v", err)
	}

	for i := 1; i <= 25; i++ {
		_, err = conn.Exec(
			ctx,
			fmt.Sprintf("INSERT INTO public.%s (email, secret_note) VALUES ($1, $2)", tableName),
			fmt.Sprintf("customer%d@example.com", i),
			fmt.Sprintf("%s_row_%d", sentinel, i),
		)
		if err != nil {
			t.Fatalf("insert dummy row %d error: %v", i, err)
		}
	}
	if _, err := conn.Exec(ctx, "ANALYZE public."+tableName); err != nil {
		t.Fatalf("ANALYZE dummy table error: %v", err)
	}

	// 3. CollectTableSnapshot should find our dummy table
	tables, err := CollectTableSnapshot(ctx, dsn)
	if err != nil {
		t.Fatalf("CollectTableSnapshot() error: %v", err)
	}
	foundTable := false
	for _, tbl := range tables {
		if tbl.Schema == "public" && tbl.Name == tableName {
			foundTable = true
			if tbl.EstimatedRows <= 0 {
				t.Errorf("expected EstimatedRows > 0 for %s, got %d", tableName, tbl.EstimatedRows)
			}
		}
	}
	if !foundTable {
		t.Fatalf("CollectTableSnapshot() did not include public.%s; got %+v", tableName, tables)
	}

	// 4. Run full encrypted streaming backup -> LocalStack S3
	bucket := fmt.Sprintf("pgvault-backup-int-%d", time.Now().UnixNano())
	s3Client := testS3Client(t, ctx, bucket)

	kek, err := crypto.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK(kek) error: %v", err)
	}

	objectKey := fmt.Sprintf("backups/customer_app/%d.pgdump.pgv1", time.Now().UnixNano())
	t.Cleanup(func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanCancel()
		_ = s3Client.DeleteObject(cleanCtx, objectKey)
	})

	result, err := RunEncryptedBackup(ctx, BackupRequest{
		DSN:       dsn,
		Storage:   s3Client,
		ObjectKey: objectKey,
		KEK:       kek,
	})
	if err != nil {
		t.Fatalf("RunEncryptedBackup() error: %v", err)
	}

	if result.ObjectKey != objectKey {
		t.Errorf("result.ObjectKey = %q, want %q", result.ObjectKey, objectKey)
	}
	if len(result.WrappedDEK) == 0 {
		t.Fatalf("result.WrappedDEK is empty")
	}
	if result.PlaintextBytes <= 0 {
		t.Errorf("result.PlaintextBytes = %d, want > 0", result.PlaintextBytes)
	}
	if result.CiphertextBytes <= 0 {
		t.Errorf("result.CiphertextBytes = %d, want > 0", result.CiphertextBytes)
	}
	if result.Duration <= 0 {
		t.Errorf("result.Duration = %v, want > 0", result.Duration)
	}
	if len(result.Tables) == 0 {
		t.Errorf("result.Tables is empty")
	}

	// 5. Download encrypted object from S3 and verify ciphertext confidentiality & integrity
	rc, err := s3Client.DownloadStream(ctx, objectKey)
	if err != nil {
		t.Fatalf("DownloadStream() error: %v", err)
	}
	encryptedBytes, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		t.Fatalf("reading downloaded ciphertext error: %v", err)
	}

	if int64(len(encryptedBytes)) != result.CiphertextBytes {
		t.Errorf("downloaded ciphertext size = %d, want %d", len(encryptedBytes), result.CiphertextBytes)
	}
	sum := sha256.Sum256(encryptedBytes)
	if gotHash := hex.EncodeToString(sum[:]); gotHash != result.CiphertextSHA256 {
		t.Errorf("downloaded ciphertext SHA256 = %q, want %q", gotHash, result.CiphertextSHA256)
	}
	if !bytes.HasPrefix(encryptedBytes, []byte(crypto.StreamMagic)) {
		t.Fatalf("encrypted object does not start with %q magic header", crypto.StreamMagic)
	}
	if bytes.Contains(encryptedBytes, []byte(sentinel)) {
		t.Fatalf("SECURITY VIOLATION: encrypted S3 object contains plaintext sentinel %q", sentinel)
	}
	if bytes.Contains(encryptedBytes, []byte(tableName)) {
		t.Fatalf("SECURITY VIOLATION: encrypted S3 object contains plaintext table name %q", tableName)
	}

	// 6. Unwrap DEK & decrypt stream, then validate PostgreSQL custom dump format
	dek, err := crypto.UnwrapDEK(kek, result.WrappedDEK)
	if err != nil {
		t.Fatalf("UnwrapDEK() error: %v", err)
	}

	var decrypted bytes.Buffer
	if err := crypto.DecryptStream(bytes.NewReader(encryptedBytes), &decrypted, dek); err != nil {
		t.Fatalf("DecryptStream() error: %v", err)
	}
	if int64(decrypted.Len()) != result.PlaintextBytes {
		t.Errorf("decrypted size = %d, want %d", decrypted.Len(), result.PlaintextBytes)
	}
	if !bytes.HasPrefix(decrypted.Bytes(), []byte("PGDMP")) {
		t.Fatalf("decrypted dump does not start with PGDMP custom-format magic")
	}

	// Verify custom dump TOC using `pg_restore --list`
	listCmd := exec.CommandContext(ctx, "pg_restore", "--list")
	listCmd.Stdin = bytes.NewReader(decrypted.Bytes())
	listOut, err := listCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("pg_restore --list failed: %v\noutput:\n%s", err, string(listOut))
	}
	if !strings.Contains(string(listOut), tableName) {
		t.Fatalf("pg_restore --list output does not mention %q:\n%s", tableName, string(listOut))
	}

	// Verify decrypted SQL output from `pg_restore -f -` contains our sentinel plaintext data
	sqlCmd := exec.CommandContext(ctx, "pg_restore", "--data-only", "-f", "-")
	sqlCmd.Stdin = bytes.NewReader(decrypted.Bytes())
	sqlOut, err := sqlCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("pg_restore --data-only failed: %v\noutput:\n%s", err, string(sqlOut))
	}
	if !strings.Contains(string(sqlOut), sentinel) {
		t.Fatalf("restored SQL does not contain sentinel %q", sentinel)
	}
}
