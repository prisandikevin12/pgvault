//go:build integration

package queue

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/prisandikevin12/pgvault/internal/db"
)

func testAppDBDSN() string {
	if dsn := os.Getenv("PGVAULT_TEST_APP_DSN"); dsn != "" {
		return dsn
	}
	return "postgres://pgvault:pgvault_dev_password@127.0.0.1:5432/pgvault?sslmode=disable"
}

func TestQueue_Integration_ConcurrentClaimSkipLocked(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := db.ConnectPool(ctx, testAppDBDSN())
	if err != nil {
		t.Fatalf("ConnectPool() error: %v", err)
	}
	defer pool.Close()

	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations() error: %v", err)
	}

	// Clean any leftover queued jobs from previous runs so counts are exact
	targetName := fmt.Sprintf("queue-conc-target-%d", time.Now().UnixNano())
	target, err := db.CreateTarget(ctx, pool, db.BackupTarget{
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

	const totalJobs = 12
	expectedIDs := make(map[int64]bool, totalJobs)
	for i := 0; i < totalJobs; i++ {
		job, err := EnqueueJob(ctx, pool, target.ID, 3, time.Now().UTC().Add(-time.Second))
		if err != nil {
			t.Fatalf("EnqueueJob(%d) error: %v", i, err)
		}
		expectedIDs[job.ID] = true
	}

	// Run 2 concurrent workers claiming jobs simultaneously.
	var (
		mu      sync.Mutex
		claimed = make(map[int64]string, totalJobs)
		dups    []int64
		wg      sync.WaitGroup
		errCh   = make(chan error, 2)
	)

	startBarrier := make(chan struct{})
	for w := 1; w <= 2; w++ {
		workerID := fmt.Sprintf("worker-%d", w)
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			<-startBarrier
			for {
				job, err := ClaimNextJob(ctx, pool, id)
				if err != nil {
					errCh <- err
					return
				}
				if job == nil {
					return
				}
				if !expectedIDs[job.ID] {
					continue
				}
				if job.Status != StatusRunning {
					errCh <- fmt.Errorf("claimed job %d has status %q, want %q", job.ID, job.Status, StatusRunning)
					return
				}
				if job.Attempts != 1 {
					errCh <- fmt.Errorf("claimed job %d has attempts %d, want 1", job.ID, job.Attempts)
					return
				}
				if job.LockedBy != id {
					errCh <- fmt.Errorf("claimed job %d has locked_by %q, want %q", job.ID, job.LockedBy, id)
					return
				}

				mu.Lock()
				if prev, exists := claimed[job.ID]; exists {
					dups = append(dups, job.ID)
					errCh <- fmt.Errorf("DUPLICATE CLAIM: job %d claimed by both %s and %s", job.ID, prev, id)
				} else {
					claimed[job.ID] = id
				}
				mu.Unlock()
			}
		}(workerID)
	}

	close(startBarrier)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("worker error: %v", err)
	}
	if len(dups) > 0 {
		t.Fatalf("duplicate job claims detected: %v", dups)
	}
	if len(claimed) != totalJobs {
		t.Fatalf("claimed %d jobs, want %d", len(claimed), totalJobs)
	}
}

func TestQueue_Integration_RequeueAndFail(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := db.ConnectPool(ctx, testAppDBDSN())
	if err != nil {
		t.Fatalf("ConnectPool() error: %v", err)
	}
	defer pool.Close()

	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations() error: %v", err)
	}

	targetName := fmt.Sprintf("queue-retry-target-%d", time.Now().UnixNano())
	target, err := db.CreateTarget(ctx, pool, db.BackupTarget{
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

	// Enqueue job with max_attempts = 2
	enqueued, err := EnqueueJob(ctx, pool, target.ID, 2, time.Now().UTC().Add(-time.Second))
	if err != nil {
		t.Fatalf("EnqueueJob() error: %v", err)
	}

	// Claim attempt 1
	job1, err := ClaimNextJob(ctx, pool, "worker-retry")
	if err != nil || job1 == nil {
		t.Fatalf("ClaimNextJob(1) = %v, %v", job1, err)
	}
	if job1.ID != enqueued.ID || job1.Attempts != 1 {
		t.Fatalf("unexpected claimed job1: %+v", job1)
	}

	// Retryable failure -> requeued with backoff in future
	status, err := RequeueOrFailJob(ctx, pool, job1.ID, "worker-retry", errors.New("temporary s3 timeout"), true, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("RequeueOrFailJob(1) error: %v", err)
	}
	if status != StatusQueued {
		t.Fatalf("status after retryable attempt 1 = %q, want %q", status, StatusQueued)
	}

	// Wait past backoff, claim attempt 2
	time.Sleep(150 * time.Millisecond)
	job2, err := ClaimNextJob(ctx, pool, "worker-retry")
	if err != nil || job2 == nil {
		t.Fatalf("ClaimNextJob(2) = %v, %v", job2, err)
	}
	if job2.ID != enqueued.ID || job2.Attempts != 2 {
		t.Fatalf("unexpected claimed job2: %+v", job2)
	}

	// Attempt 2 == max_attempts -> must transition to failed
	status, err = RequeueOrFailJob(ctx, pool, job2.ID, "worker-retry", errors.New("still failing"), true, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("RequeueOrFailJob(2) error: %v", err)
	}
	if status != StatusFailed {
		t.Fatalf("status after max attempts = %q, want %q", status, StatusFailed)
	}

	finalJob, err := GetJob(ctx, pool, enqueued.ID)
	if err != nil {
		t.Fatalf("GetJob() error: %v", err)
	}
	if finalJob.Status != StatusFailed || finalJob.FinishedAt == nil {
		t.Fatalf("expected failed job with finished_at set, got %+v", finalJob)
	}
}
