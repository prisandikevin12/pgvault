//go:build integration

package db

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

func testAppDBDSN() string {
	if dsn := os.Getenv("PGVAULT_TEST_APP_DSN"); dsn != "" {
		return dsn
	}
	return "postgres://pgvault:pgvault_dev_password@127.0.0.1:5432/pgvault?sslmode=disable"
}

func TestApplyMigrations_Integration_Idempotent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := ConnectPool(ctx, testAppDBDSN())
	if err != nil {
		t.Fatalf("ConnectPool() error: %v", err)
	}
	t.Cleanup(pool.Close)

	// Calling ApplyMigrations twice must succeed idempotently.
	if err := ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations() first run error: %v", err)
	}
	if err := ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations() second run error: %v", err)
	}

	// Verify all required tables exist.
	for _, tbl := range []string{"backup_targets", "backup_jobs", "backup_artifacts", "alert_channels"} {
		var exists bool
		err := pool.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM information_schema.tables
				WHERE table_schema = 'public' AND table_name = $1
			)
		`, tbl).Scan(&exists)
		if err != nil {
			t.Fatalf("check table %s existence error: %v", tbl, err)
		}
		if !exists {
			t.Fatalf("expected table %q to exist after ApplyMigrations", tbl)
		}
	}

	// Verify 002 scheduler/lease & 003 retention columns exist.
	for _, col := range [][2]string{
		{"backup_targets", "last_scheduled_at"},
		{"backup_targets", "retention_keep_last"},
		{"backup_targets", "retention_max_age_days"},
		{"backup_jobs", "lease_expires_at"},
		{"backup_artifacts", "pruned_at"},
	} {
		var colExists bool
		err := pool.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2
			)
		`, col[0], col[1]).Scan(&colExists)
		if err != nil {
			t.Fatalf("check column %s.%s error: %v", col[0], col[1], err)
		}
		if !colExists {
			t.Fatalf("expected column %s.%s to exist after ApplyMigrations", col[0], col[1])
		}
	}

	// Quick round-trip CreateTarget + GetTarget + CreateAlertChannel
	targetName := fmt.Sprintf("db-int-target-%d", time.Now().UnixNano())
	target, err := CreateTarget(ctx, pool, BackupTarget{
		Name:                  targetName,
		TargetDSN:             "postgres://example",
		StorageEndpoint:       "http://127.0.0.1:4566",
		StorageRegion:         "us-east-1",
		StorageBucket:         "pgvault-test",
		StorageAccessKey:      "test",
		StorageSecretKey:      "test",
		StorageForcePathStyle: true,
		IntervalSeconds:       3600,
	})
	if err != nil {
		t.Fatalf("CreateTarget() error: %v", err)
	}
	t.Cleanup(func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanCancel()
		_, _ = pool.Exec(cleanCtx, "DELETE FROM backup_targets WHERE id = $1", target.ID)
	})

	fetched, err := GetTarget(ctx, pool, target.ID)
	if err != nil {
		t.Fatalf("GetTarget() error: %v", err)
	}
	if fetched.Name != targetName {
		t.Errorf("GetTarget().Name = %q, want %q", fetched.Name, targetName)
	}
}

func TestDB_Integration_CreateArtifact_UpsertOnJobRetry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := ConnectPool(ctx, testAppDBDSN())
	if err != nil {
		t.Fatalf("ConnectPool() error: %v", err)
	}
	t.Cleanup(pool.Close)

	if err := ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations() error: %v", err)
	}

	targetName := fmt.Sprintf("retry-artifact-target-%d", time.Now().UnixNano())
	target, err := CreateTarget(ctx, pool, BackupTarget{
		Name:            targetName,
		TargetDSN:       "postgres://example",
		StorageRegion:   "us-east-1",
		StorageBucket:   "pgvault-test",
		IntervalSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("CreateTarget() error: %v", err)
	}
	t.Cleanup(func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanCancel()
		_, _ = pool.Exec(cleanCtx, "DELETE FROM backup_targets WHERE id = $1", target.ID)
	})

	var jobID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO backup_jobs (target_id, status, attempts, max_attempts)
		VALUES ($1, 'running', 1, 3)
		RETURNING id
	`, target.ID).Scan(&jobID); err != nil {
		t.Fatalf("insert job error: %v", err)
	}

	// Attempt 1 uploads artifact, then fails verification
	art1, err := CreateArtifact(ctx, pool, BackupArtifact{
		JobID:              jobID,
		TargetID:           target.ID,
		ObjectKey:          "backups/attempt-1.pgv",
		WrappedDEK:         []byte("dek-attempt-1"),
		PlaintextBytes:     100,
		CiphertextBytes:    120,
		CiphertextSHA256:   "hash-attempt-1",
		PGMajorVersion:     16,
		VerificationPassed: false,
		VerificationError:  "transient docker error",
	})
	if err != nil {
		t.Fatalf("CreateArtifact(attempt 1) error: %v", err)
	}

	// Attempt 2 retries the same job_id -> must upsert cleanly without unique constraint violation
	art2, err := CreateArtifact(ctx, pool, BackupArtifact{
		JobID:              jobID,
		TargetID:           target.ID,
		ObjectKey:          "backups/attempt-2.pgv",
		WrappedDEK:         []byte("dek-attempt-2"),
		PlaintextBytes:     200,
		CiphertextBytes:    240,
		CiphertextSHA256:   "hash-attempt-2",
		PGMajorVersion:     16,
		VerificationPassed: false,
		VerificationError:  "",
	})
	if err != nil {
		t.Fatalf("CreateArtifact(attempt 2 retry) error: %v", err)
	}
	if art2.ID != art1.ID {
		t.Errorf("upserted artifact ID = %d, want existing row ID %d", art2.ID, art1.ID)
	}
	if art2.ObjectKey != "backups/attempt-2.pgv" || art2.CiphertextSHA256 != "hash-attempt-2" || art2.VerificationError != "" {
		t.Errorf("upserted artifact fields not refreshed: %+v", art2)
	}
}
