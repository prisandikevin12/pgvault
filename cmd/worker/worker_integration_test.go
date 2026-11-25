//go:build integration

package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/prisandikevin12/pgvault/internal/crypto"
	"github.com/prisandikevin12/pgvault/internal/db"
	"github.com/prisandikevin12/pgvault/internal/notify"
	"github.com/prisandikevin12/pgvault/internal/queue"
	"github.com/prisandikevin12/pgvault/internal/storage"
)

type recordingNotifier struct {
	mu     sync.Mutex
	events []notify.Event
}

func (r *recordingNotifier) Notify(_ context.Context, event notify.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
	return nil
}

func testEnvOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func TestWorker_Integration_EndToEndBackupAndVerify(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	appDSN := testEnvOrDefault("PGVAULT_TEST_APP_DSN", "postgres://pgvault:pgvault_dev_password@127.0.0.1:5432/pgvault?sslmode=disable")
	targetDSN := testEnvOrDefault("PGVAULT_TEST_TARGET_DSN", "postgres://target_admin:target_dev_password@127.0.0.1:5433/customer_app?sslmode=disable")
	s3Endpoint := testEnvOrDefault("PGVAULT_TEST_S3_ENDPOINT", "http://127.0.0.1:4566")
	s3Region := testEnvOrDefault("PGVAULT_TEST_S3_REGION", "us-east-1")
	s3AccessKey := testEnvOrDefault("PGVAULT_TEST_S3_ACCESS_KEY", "test")
	s3SecretKey := testEnvOrDefault("PGVAULT_TEST_S3_SECRET_KEY", "test")

	// 1. Connect to app-db and apply migrations
	pool, err := db.ConnectPool(ctx, appDSN)
	if err != nil {
		t.Fatalf("ConnectPool(app-db) error: %v", err)
	}
	defer pool.Close()

	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations() error: %v", err)
	}

	// 2. Seed dummy table in target-db
	targetConn, err := pgx.Connect(ctx, targetDSN)
	if err != nil {
		t.Fatalf("pgx.Connect(target-db) error: %v", err)
	}
	defer targetConn.Close(context.Background())

	const tableName = "pgvault_e2e_invoices"
	t.Cleanup(func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanCancel()
		c, err := pgx.Connect(cleanCtx, targetDSN)
		if err == nil {
			_, _ = c.Exec(cleanCtx, "DROP TABLE IF EXISTS public."+tableName)
			_ = c.Close(cleanCtx)
		}
	})

	_, err = targetConn.Exec(ctx, fmt.Sprintf(`
		DROP TABLE IF EXISTS public.%s;
		CREATE TABLE public.%s (
			id SERIAL PRIMARY KEY,
			invoice_no TEXT NOT NULL,
			amount_cents BIGINT NOT NULL
		);
		INSERT INTO public.%s (invoice_no, amount_cents)
		SELECT 'INV-' || g, g * 1000 FROM generate_series(1, 15) AS g;
		ANALYZE public.%s;
	`, tableName, tableName, tableName, tableName))
	if err != nil {
		t.Fatalf("seed target-db error: %v", err)
	}

	// 3. Ensure S3 bucket exists in LocalStack
	bucket := fmt.Sprintf("pgvault-worker-e2e-%d", time.Now().UnixNano())
	s3Client, err := storage.NewClient(ctx, storage.Config{
		EndpointURL:     s3Endpoint,
		Region:          s3Region,
		Bucket:          bucket,
		AccessKeyID:     s3AccessKey,
		SecretAccessKey: s3SecretKey,
		ForcePathStyle:  true,
	})
	if err != nil {
		t.Fatalf("storage.NewClient() error: %v", err)
	}
	if err := s3Client.EnsureBucket(ctx); err != nil {
		t.Fatalf("EnsureBucket() error: %v", err)
	}

	// 4. Encrypt target credentials with KEK, insert backup_target & backup_job
	kek, err := crypto.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK(kek) error: %v", err)
	}
	protectedDSN, err := db.ProtectSecret(kek, targetDSN)
	if err != nil {
		t.Fatalf("ProtectSecret(dsn) error: %v", err)
	}
	protectedS3Secret, err := db.ProtectSecret(kek, s3SecretKey)
	if err != nil {
		t.Fatalf("ProtectSecret(s3Secret) error: %v", err)
	}

	targetName := fmt.Sprintf("e2e-customer-app-%d", time.Now().UnixNano())
	target, err := db.CreateTarget(ctx, pool, db.BackupTarget{
		Name:                  targetName,
		TargetDSN:             protectedDSN,
		StorageEndpoint:       s3Endpoint,
		StorageRegion:         s3Region,
		StorageBucket:         bucket,
		StorageAccessKey:      s3AccessKey,
		StorageSecretKey:      protectedS3Secret,
		StorageForcePathStyle: true,
		SanityQuery:           fmt.Sprintf("SELECT count(*) FROM public.%s", tableName),
		IntervalSeconds:       3600,
	})
	if err != nil {
		t.Fatalf("CreateTarget() error: %v", err)
	}
	t.Cleanup(func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanCancel()
		_, _ = pool.Exec(cleanCtx, "DELETE FROM backup_targets WHERE id = $1", target.ID)
	})

	job, err := queue.EnqueueJob(ctx, pool, target.ID, 3, time.Now().UTC().Add(-time.Second))
	if err != nil {
		t.Fatalf("EnqueueJob() error: %v", err)
	}

	// 5. Run one worker cycle end-to-end
	recNotifier := &recordingNotifier{}
	worker, err := NewWorker(pool, WorkerConfig{
		WorkerID:      "e2e-worker-1",
		KEK:           kek,
		VerifyTimeout: 2 * time.Minute,
	}, recNotifier, nil)
	if err != nil {
		t.Fatalf("NewWorker() error: %v", err)
	}

	processed, err := worker.ProcessOnce(ctx)
	if err != nil {
		t.Fatalf("worker.ProcessOnce() error: %v", err)
	}
	if !processed {
		t.Fatalf("worker.ProcessOnce() returned processed=false, want true")
	}

	// 6. Verify job status == succeeded
	updatedJob, err := queue.GetJob(ctx, pool, job.ID)
	if err != nil {
		t.Fatalf("GetJob() error: %v", err)
	}
	if updatedJob.Status != queue.StatusSucceeded {
		t.Fatalf("job.Status = %q, want %q (error_message=%q)", updatedJob.Status, queue.StatusSucceeded, updatedJob.ErrorMessage)
	}
	if updatedJob.FinishedAt == nil {
		t.Errorf("expected job.FinishedAt to be set")
	}

	// 7. Verify backup_artifacts persisted with verification_passed = true
	artifact, err := db.GetArtifactByJobID(ctx, pool, job.ID)
	if err != nil {
		t.Fatalf("GetArtifactByJobID() error: %v", err)
	}
	t.Cleanup(func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanCancel()
		_ = s3Client.DeleteObject(cleanCtx, artifact.ObjectKey)
	})

	if !artifact.VerificationPassed {
		t.Fatalf("artifact.VerificationPassed = false, want true (verification_error=%q)", artifact.VerificationError)
	}
	if artifact.PlaintextBytes <= 0 || artifact.CiphertextBytes <= 0 || artifact.CiphertextSHA256 == "" {
		t.Errorf("unexpected artifact stats: %+v", artifact)
	}
	if len(artifact.WrappedDEK) == 0 {
		t.Errorf("expected non-empty wrapped_dek")
	}
	if artifact.PGMajorVersion != 16 {
		t.Errorf("artifact.PGMajorVersion = %d, want 16", artifact.PGMajorVersion)
	}

	// 8. Verify notifier was called with success event and contains no secrets
	recNotifier.mu.Lock()
	defer recNotifier.mu.Unlock()
	if len(recNotifier.events) != 1 {
		t.Fatalf("expected 1 notification event, got %d", len(recNotifier.events))
	}
	ev := recNotifier.events[0]
	if ev.Type != notify.EventBackupSucceeded || ev.JobID != job.ID || !ev.VerificationPassed {
		t.Errorf("unexpected notification event: %+v", ev)
	}
	formatted := notify.FormatEventMessage(ev)
	if strings.Contains(formatted, "target_dev_password") {
		t.Errorf("SECURITY VIOLATION: notification message leaked DB password: %q", formatted)
	}
}

func TestWorker_Integration_MaintenanceSchedulerAndRecovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	appDSN := testEnvOrDefault("PGVAULT_TEST_APP_DSN", "postgres://pgvault:pgvault_dev_password@127.0.0.1:5432/pgvault?sslmode=disable")
	pool, err := db.ConnectPool(ctx, appDSN)
	if err != nil {
		t.Fatalf("ConnectPool() error: %v", err)
	}
	t.Cleanup(pool.Close)

	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations() error: %v", err)
	}

	kek, _ := crypto.GenerateDEK()
	targetName := fmt.Sprintf("worker-maint-%d", time.Now().UnixNano())
	target, err := db.CreateTarget(ctx, pool, db.BackupTarget{
		Name:            targetName,
		TargetDSN:       "postgres://example",
		StorageRegion:   "us-east-1",
		StorageBucket:   "pgvault-test",
		IntervalSeconds: 300,
	})
	if err != nil {
		t.Fatalf("CreateTarget() error: %v", err)
	}
	t.Cleanup(func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanCancel()
		_, _ = pool.Exec(cleanCtx, "DELETE FROM backup_targets WHERE id = $1", target.ID)
	})

	worker, err := NewWorker(pool, WorkerConfig{
		WorkerID:          "maint-worker",
		KEK:               kek,
		SchedulerInterval: 10 * time.Second,
		JobLeaseDuration:  5 * time.Minute,
	}, &recordingNotifier{}, nil)
	if err != nil {
		t.Fatalf("NewWorker() error: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)

	// 1. RunMaintenanceOnce schedules the due target (last_scheduled_at is NULL).
	recovered, scheduled, err := worker.RunMaintenanceOnce(ctx, now)
	if err != nil {
		t.Fatalf("RunMaintenanceOnce(1) error: %v", err)
	}
	if scheduled < 1 {
		t.Fatalf("RunMaintenanceOnce(1) scheduled = %d, want >= 1 (recovered=%d)", scheduled, recovered)
	}

	jobs, err := queue.ListJobs(ctx, pool, &target.ID, queue.StatusQueued, 5)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("ListJobs() = %+v, %v; want 1 scheduled job", jobs, err)
	}

	// 2. Simulate crashed worker with expired lease on that job, then verify RunMaintenanceOnce recovers it.
	if _, err := pool.Exec(ctx, `
		UPDATE backup_jobs
		SET status = 'running', attempts = 1, locked_at = $2, locked_by = 'crashed-worker', lease_expires_at = $3
		WHERE id = $1
	`, jobs[0].ID, now.Add(-10*time.Minute), now.Add(-5*time.Minute)); err != nil {
		t.Fatalf("simulate expired lease error: %v", err)
	}

	recovered, _, err = worker.RunMaintenanceOnce(ctx, now)
	if err != nil {
		t.Fatalf("RunMaintenanceOnce(2) error: %v", err)
	}
	if recovered < 1 {
		t.Fatalf("RunMaintenanceOnce(2) recovered = %d, want >= 1", recovered)
	}

	got, err := queue.GetJob(ctx, pool, jobs[0].ID)
	if err != nil {
		t.Fatalf("GetJob() error: %v", err)
	}
	if got.Status != queue.StatusQueued || got.LeaseExpiresAt != nil || got.ErrorMessage != queue.StaleJobRecoveredError {
		t.Fatalf("unexpected job state after worker maintenance recovery: %+v", got)
	}
}
