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
	defer pool.Close()

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
