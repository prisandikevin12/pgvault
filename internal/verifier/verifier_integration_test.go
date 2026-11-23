//go:build integration

package verifier

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/containerd/errdefs"
	"github.com/docker/docker/client"
	"github.com/jackc/pgx/v5"
	"github.com/prisandikevin12/pgvault/internal/crypto"
	"github.com/prisandikevin12/pgvault/internal/pgdump"
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

	s3Client, err := storage.NewClient(ctx, storage.Config{
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
	if err := s3Client.EnsureBucket(ctx); err != nil {
		t.Fatalf("EnsureBucket() error: %v", err)
	}
	return s3Client
}

func assertContainerRemoved(t *testing.T, ctx context.Context, containerID string) {
	t.Helper()
	if containerID == "" {
		t.Fatalf("expected non-empty ContainerID to verify container cleanup")
	}
	dockerCli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatalf("docker client error: %v", err)
	}
	defer dockerCli.Close()

	_, err = dockerCli.ContainerInspect(ctx, containerID)
	if err == nil {
		t.Fatalf("verification container %s still exists after RunVerification returned", containerID)
	}
	if !errdefs.IsNotFound(err) {
		t.Fatalf("ContainerInspect(%s) unexpected error (want NotFound): %v", containerID, err)
	}
}

func TestVerifier_Integration_ValidAndCorruptedBackups(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	dsn := testTargetDSN()

	// Seed dummy table + rows in target-db
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("pgx.Connect() error: %v", err)
	}
	defer conn.Close(context.Background())

	const (
		tableName = "pgvault_verify_orders"
		sentinel  = "PGVAULT_VERIFY_SENSITIVE_DATA_424242"
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
			order_ref TEXT NOT NULL,
			secret_payload TEXT NOT NULL
		);
	`, tableName, tableName))
	if err != nil {
		t.Fatalf("create dummy table error: %v", err)
	}

	for i := 1; i <= 20; i++ {
		_, err = conn.Exec(
			ctx,
			fmt.Sprintf("INSERT INTO public.%s (order_ref, secret_payload) VALUES ($1, $2)", tableName),
			fmt.Sprintf("ORD-%04d", i),
			fmt.Sprintf("%s_%d", sentinel, i),
		)
		if err != nil {
			t.Fatalf("insert dummy row %d error: %v", i, err)
		}
	}
	if _, err := conn.Exec(ctx, "ANALYZE public."+tableName); err != nil {
		t.Fatalf("ANALYZE error: %v", err)
	}

	majorVersion, err := pgdump.DetectMajorVersion(ctx, dsn)
	if err != nil {
		t.Fatalf("DetectMajorVersion() error: %v", err)
	}

	bucket := fmt.Sprintf("pgvault-verify-int-%d", time.Now().UnixNano())
	s3Client := testS3Client(t, ctx, bucket)

	kek, err := crypto.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK() error: %v", err)
	}

	validKey := fmt.Sprintf("backups/valid-%d.pgv1", time.Now().UnixNano())
	corruptKey := fmt.Sprintf("backups/corrupt-%d.pgv1", time.Now().UnixNano())
	t.Cleanup(func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanCancel()
		_ = s3Client.DeleteObject(cleanCtx, validKey)
		_ = s3Client.DeleteObject(cleanCtx, corruptKey)
	})

	backupRes, err := pgdump.RunEncryptedBackup(ctx, pgdump.BackupRequest{
		DSN:       dsn,
		Storage:   s3Client,
		ObjectKey: validKey,
		KEK:       kek,
	})
	if err != nil {
		t.Fatalf("RunEncryptedBackup() error: %v", err)
	}

	// Scenario 1: Valid Backup -> Passed: true, RestoredTables matches, container removed
	t.Run("valid_backup", func(t *testing.T) {
		verifyRes, err := RunVerification(ctx, VerifyRequest{
			Storage:        s3Client,
			ObjectKey:      validKey,
			WrappedDEK:     backupRes.WrappedDEK,
			KEK:            kek,
			ExpectedTables: backupRes.Tables,
			SanityQuery:    fmt.Sprintf("SELECT count(*) FROM public.%s WHERE order_ref LIKE 'ORD-%%'", tableName),
			PGMajorVersion: majorVersion,
			Timeout:        2 * time.Minute,
		})
		if err != nil {
			t.Fatalf("RunVerification(valid) unexpected error: %v (result=%+v)", err, verifyRes)
		}
		if verifyRes == nil {
			t.Fatalf("RunVerification(valid) returned nil result")
		}
		if !verifyRes.Passed {
			t.Errorf("VerifyResult.Passed = false, want true (error=%q, logs=%q)", verifyRes.Error, verifyRes.LogsTail)
		}
		if !verifyRes.SanityQueryPassed {
			t.Errorf("VerifyResult.SanityQueryPassed = false, want true")
		}
		if verifyRes.ExpectedTables != len(backupRes.Tables) {
			t.Errorf("VerifyResult.ExpectedTables = %d, want %d", verifyRes.ExpectedTables, len(backupRes.Tables))
		}
		if verifyRes.RestoredTables != len(backupRes.Tables) {
			t.Errorf("VerifyResult.RestoredTables = %d, want %d", verifyRes.RestoredTables, len(backupRes.Tables))
		}
		if verifyRes.PGVersionUsed < majorVersion {
			t.Errorf("VerifyResult.PGVersionUsed = %d, want >= %d", verifyRes.PGVersionUsed, majorVersion)
		}
		if verifyRes.RestoreDurationMs < 0 {
			t.Errorf("VerifyResult.RestoreDurationMs = %d, want >= 0", verifyRes.RestoreDurationMs)
		}
		if bytes.Contains([]byte(verifyRes.LogsTail), []byte(sentinel)) {
			t.Errorf("SECURITY VIOLATION: LogsTail leaked sensitive table data")
		}

		assertContainerRemoved(t, ctx, verifyRes.ContainerID)
	})

	// Scenario 2: Corrupted Backup -> Passed: false, clear error, container still cleaned up
	t.Run("corrupted_ciphertext", func(t *testing.T) {
		rc, err := s3Client.DownloadStream(ctx, validKey)
		if err != nil {
			t.Fatalf("DownloadStream(validKey) error: %v", err)
		}
		raw, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatalf("ReadAll(validKey) error: %v", err)
		}

		// Flip 1 bit in the last ciphertext byte
		corrupted := append([]byte(nil), raw...)
		corrupted[len(corrupted)-1] ^= 0x01

		if _, err := s3Client.UploadStream(ctx, corruptKey, bytes.NewReader(corrupted), "application/octet-stream"); err != nil {
			t.Fatalf("UploadStream(corruptKey) error: %v", err)
		}

		verifyRes, err := RunVerification(ctx, VerifyRequest{
			Storage:        s3Client,
			ObjectKey:      corruptKey,
			WrappedDEK:     backupRes.WrappedDEK,
			KEK:            kek,
			ExpectedTables: backupRes.Tables,
			PGMajorVersion: majorVersion,
			Timeout:        2 * time.Minute,
		})
		if err == nil {
			t.Fatalf("RunVerification(corrupted) succeeded, want error")
		}
		if verifyRes == nil {
			t.Fatalf("RunVerification(corrupted) returned nil result")
		}
		if verifyRes.Passed {
			t.Errorf("VerifyResult.Passed = true on corrupted backup, want false")
		}
		if verifyRes.Error == "" {
			t.Errorf("VerifyResult.Error is empty on corrupted backup")
		}

		assertContainerRemoved(t, ctx, verifyRes.ContainerID)
	})
}
