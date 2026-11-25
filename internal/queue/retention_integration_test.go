//go:build integration

package queue

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/aws/smithy-go"
	"github.com/prisandikevin12/pgvault/internal/db"
)

type fakeObjectDeleter struct {
	mu      sync.Mutex
	deleted []string
	errByKey map[string]error
}

func (f *fakeObjectDeleter) DeleteObject(_ context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.errByKey[key]; ok {
		return err
	}
	f.deleted = append(f.deleted, key)
	return nil
}

func TestQueue_Integration_PruneExpiredBackups(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := db.ConnectPool(ctx, testAppDBDSN())
	if err != nil {
		t.Fatalf("ConnectPool() error: %v", err)
	}
	t.Cleanup(pool.Close)

	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations() error: %v", err)
	}

	targetName := fmt.Sprintf("prune-target-%d", time.Now().UnixNano())
	target, err := db.CreateTarget(ctx, pool, db.BackupTarget{
		Name:                targetName,
		TargetDSN:           "postgres://example",
		StorageRegion:       "us-east-1",
		StorageBucket:       "pgvault-test",
		IntervalSeconds:     3600,
		RetentionKeepLast:   2,
		RetentionMaxAgeDays: 7,
	})
	if err != nil {
		t.Fatalf("CreateTarget() error: %v", err)
	}
	t.Cleanup(func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanCancel()
		_, _ = pool.Exec(cleanCtx, "DELETE FROM backup_targets WHERE id = $1", target.ID)
	})

	now := time.Now().UTC().Truncate(time.Second)

	seedJobArtifact := func(status string, key string, age time.Duration) (int64, int64) {
		t.Helper()
		j, err := EnqueueJob(ctx, pool, target.ID, 3, now.Add(-age))
		if err != nil {
			t.Fatalf("EnqueueJob(%s) error: %v", key, err)
		}
		if _, err := pool.Exec(ctx, "UPDATE backup_jobs SET status = $2, created_at = $3 WHERE id = $1", j.ID, status, now.Add(-age)); err != nil {
			t.Fatalf("update job %d status error: %v", j.ID, err)
		}
		art, err := db.CreateArtifact(ctx, pool, db.BackupArtifact{
			JobID:              j.ID,
			TargetID:           target.ID,
			ObjectKey:          key,
			WrappedDEK:         []byte("dek"),
			PlaintextBytes:     100,
			CiphertextBytes:    120,
			CiphertextSHA256:   "deadbeef",
			PGMajorVersion:     16,
			VerificationPassed: status == StatusSucceeded,
		})
		if err != nil {
			t.Fatalf("CreateArtifact(%s) error: %v", key, err)
		}
		if _, err := pool.Exec(ctx, "UPDATE backup_artifacts SET created_at = $2 WHERE id = $1", art.ID, now.Add(-age)); err != nil {
			t.Fatalf("update artifact %d created_at error: %v", art.ID, err)
		}
		return j.ID, art.ID
	}

	// 1. Succeeded newest (1h old) -> MUST KEEP
	jKeep1, _ := seedJobArtifact(StatusSucceeded, "backups/keep-1.pgv1", 1*time.Hour)
	// 2. Succeeded 2nd newest (2h old) -> MUST KEEP
	jKeep2, _ := seedJobArtifact(StatusSucceeded, "backups/keep-2.pgv1", 2*time.Hour)
	// 3. Succeeded 3rd (3h old, exceeds keep_last=2) -> MUST PRUNE (S3 returns nil)
	jPruneOK, _ := seedJobArtifact(StatusSucceeded, "backups/prune-ok.pgv1", 3*time.Hour)
	// 4. Succeeded 4th (10d old, exceeds both) -> S3 returns NoSuchKey -> MUST IGNORE NoSuchKey AND MARK PRUNED
	jPruneMissing, _ := seedJobArtifact(StatusSucceeded, "backups/prune-missing.pgv1", 10*24*time.Hour)
	// 5. Succeeded 5th (12d old) -> S3 returns 500 InternalError -> MUST NOT MARK PRUNED
	jPruneErr, _ := seedJobArtifact(StatusSucceeded, "backups/prune-s3err.pgv1", 12*24*time.Hour)
	// 6. Active verifying job (20d old) -> MUST NEVER PRUNE
	jVerifying, _ := seedJobArtifact(StatusVerifying, "backups/active-verifying.pgv1", 20*24*time.Hour)

	deleter := &fakeObjectDeleter{
		errByKey: map[string]error{
			"backups/prune-missing.pgv1": &smithy.GenericAPIError{Code: "NoSuchKey", Message: "The specified key does not exist"},
			"backups/prune-s3err.pgv1":   errors.New("s3 503 service unavailable"),
		},
	}

	q := New(pool)
	summary, pruneErr := q.PruneExpiredBackups(ctx, now, func(_ context.Context, _ db.BackupTarget) (ObjectDeleter, error) {
		return deleter, nil
	})
	if pruneErr == nil {
		t.Fatalf("expected non-nil error due to simulated S3 503 on prune-s3err.pgv1")
	}
	if summary.ObjectsPruned < 2 || summary.Errors < 1 {
		t.Fatalf("unexpected PruneSummary: %+v", summary)
	}

	checkPruned := func(jobID int64, wantPruned bool) {
		t.Helper()
		art, err := db.GetArtifactByJobID(ctx, pool, jobID)
		if err != nil {
			t.Fatalf("GetArtifactByJobID(%d) error: %v", jobID, err)
		}
		if (art.PrunedAt != nil) != wantPruned {
			t.Errorf("job %d (%s) pruned_at=%v, wantPruned=%v", jobID, art.ObjectKey, art.PrunedAt, wantPruned)
		}
	}

	checkPruned(jKeep1, false)
	checkPruned(jKeep2, false)
	checkPruned(jPruneOK, true)
	checkPruned(jPruneMissing, true)
	checkPruned(jPruneErr, false)
	checkPruned(jVerifying, false)

	// Retry after S3 recovers -> prune-s3err.pgv1 succeeds and gets marked pruned
	delete(deleter.errByKey, "backups/prune-s3err.pgv1")
	summary2, err := q.PruneExpiredBackups(ctx, now, func(_ context.Context, _ db.BackupTarget) (ObjectDeleter, error) {
		return deleter, nil
	})
	if err != nil {
		t.Fatalf("second PruneExpiredBackups() unexpected error: %v", err)
	}
	if summary2.ObjectsPruned < 1 {
		t.Fatalf("expected retry prune to prune >= 1 object, got %+v", summary2)
	}
	checkPruned(jPruneErr, true)
}

func TestQueue_Integration_PruneExpiredBackups_ConcurrentWorkersSafe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := db.ConnectPool(ctx, testAppDBDSN())
	if err != nil {
		t.Fatalf("ConnectPool() error: %v", err)
	}
	t.Cleanup(pool.Close)

	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations() error: %v", err)
	}

	targetName := fmt.Sprintf("prune-race-target-%d", time.Now().UnixNano())
	target, err := db.CreateTarget(ctx, pool, db.BackupTarget{
		Name:                targetName,
		TargetDSN:           "postgres://example",
		StorageRegion:       "us-east-1",
		StorageBucket:       "pgvault-test",
		IntervalSeconds:     3600,
		RetentionKeepLast:   1,
		RetentionMaxAgeDays: 0,
	})
	if err != nil {
		t.Fatalf("CreateTarget() error: %v", err)
	}
	t.Cleanup(func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanCancel()
		_, _ = pool.Exec(cleanCtx, "DELETE FROM backup_targets WHERE id = $1", target.ID)
	})

	now := time.Now().UTC().Truncate(time.Second)
	for i, age := range []time.Duration{1 * time.Hour, 2 * time.Hour, 3 * time.Hour} {
		j, err := EnqueueJob(ctx, pool, target.ID, 3, now.Add(-age))
		if err != nil {
			t.Fatalf("EnqueueJob(%d) error: %v", i, err)
		}
		_, _ = pool.Exec(ctx, "UPDATE backup_jobs SET status = 'succeeded', created_at = $2 WHERE id = $1", j.ID, now.Add(-age))
		art, err := db.CreateArtifact(ctx, pool, db.BackupArtifact{
			JobID:              j.ID,
			TargetID:           target.ID,
			ObjectKey:          fmt.Sprintf("backups/race-%d-%d.pgv1", target.ID, i),
			WrappedDEK:         []byte("dek"),
			PlaintextBytes:     100,
			CiphertextBytes:    120,
			CiphertextSHA256:   "deadbeef",
			PGMajorVersion:     16,
			VerificationPassed: true,
		})
		if err != nil {
			t.Fatalf("CreateArtifact(%d) error: %v", i, err)
		}
		_, _ = pool.Exec(ctx, "UPDATE backup_artifacts SET created_at = $2 WHERE id = $1", art.ID, now.Add(-age))
	}

	slowDeleter := &slowObjectDeleter{delay: 120 * time.Millisecond}
	q := New(pool)

	var (
		wg          sync.WaitGroup
		mu          sync.Mutex
		totalErrors int
		totalPruned int
		pruneErrs   []error
		barrier     = make(chan struct{})
	)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-barrier
			sum, err := q.PruneExpiredBackups(ctx, now, func(_ context.Context, _ db.BackupTarget) (ObjectDeleter, error) {
				return slowDeleter, nil
			})
			mu.Lock()
			totalErrors += sum.Errors
			totalPruned += sum.ObjectsPruned
			if err != nil {
				pruneErrs = append(pruneErrs, err)
			}
			mu.Unlock()
		}()
	}
	close(barrier)
	wg.Wait()

	if len(pruneErrs) > 0 || totalErrors > 0 {
		t.Fatalf("concurrent PruneExpiredBackups produced errors: totalErrors=%d errs=%v", totalErrors, pruneErrs)
	}
	if totalPruned < 2 {
		t.Fatalf("totalPruned = %d, want >= 2", totalPruned)
	}

	// Ensure no object key was deleted twice
	seen := make(map[string]int)
	for _, k := range slowDeleter.deleted {
		seen[k]++
		if seen[k] > 1 {
			t.Errorf("object key %q was deleted %d times concurrently (want 1)", k, seen[k])
		}
	}
}

type slowObjectDeleter struct {
	mu      sync.Mutex
	delay   time.Duration
	deleted []string
}

func (s *slowObjectDeleter) DeleteObject(_ context.Context, key string) error {
	time.Sleep(s.delay)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleted = append(s.deleted, key)
	return nil
}
