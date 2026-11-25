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
	t.Cleanup(pool.Close)

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
	t.Cleanup(pool.Close)

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
	if finalJob.LeaseExpiresAt != nil {
		t.Fatalf("expected failed job lease_expires_at to be NULL, got %v", finalJob.LeaseExpiresAt)
	}
}

func TestQueue_Integration_AutoScheduler(t *testing.T) {
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

	targetName := fmt.Sprintf("sched-target-%d", time.Now().UnixNano())
	target, err := db.CreateTarget(ctx, pool, db.BackupTarget{
		Name:            targetName,
		TargetDSN:       "postgres://example",
		StorageRegion:   "us-east-1",
		StorageBucket:   "pgvault-test",
		IntervalSeconds: 600,
	})
	if err != nil {
		t.Fatalf("CreateTarget() error: %v", err)
	}
	t.Cleanup(func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanCancel()
		_, _ = pool.Exec(cleanCtx, "DELETE FROM backup_targets WHERE id = $1", target.ID)
	})

	q := New(pool)
	t0 := time.Now().UTC().Truncate(time.Second)

	// 1. Target with last_scheduled_at = NULL is immediately scheduled once and last_scheduled_at is populated.
	n, err := q.EnqueueDueScheduledTargets(ctx, t0)
	if err != nil {
		t.Fatalf("EnqueueDueScheduledTargets(t0) error: %v", err)
	}
	if n < 1 {
		t.Fatalf("EnqueueDueScheduledTargets(t0) = %d, want >= 1", n)
	}

	jobs, err := ListJobs(ctx, pool, &target.ID, "", 10)
	if err != nil {
		t.Fatalf("ListJobs() error: %v", err)
	}
	if len(jobs) != 1 || jobs[0].Status != StatusQueued || jobs[0].Attempts != 0 {
		t.Fatalf("expected 1 queued job with attempts=0, got %+v", jobs)
	}
	updatedTarget, err := db.GetTarget(ctx, pool, target.ID)
	if err != nil {
		t.Fatalf("GetTarget() error: %v", err)
	}
	if updatedTarget.LastScheduledAt == nil || !updatedTarget.LastScheduledAt.UTC().Equal(t0) {
		t.Fatalf("LastScheduledAt = %v, want %v", updatedTarget.LastScheduledAt, t0)
	}

	// 2. Before interval elapses, target is not re-scheduled.
	t1 := t0.Add(5 * time.Minute)
	if _, err := q.EnqueueDueScheduledTargets(ctx, t1); err != nil {
		t.Fatalf("EnqueueDueScheduledTargets(t1) error: %v", err)
	}
	jobs, _ = ListJobs(ctx, pool, &target.ID, "", 10)
	if len(jobs) != 1 {
		t.Fatalf("expected still 1 job before interval elapsed, got %d", len(jobs))
	}

	// 3. Past interval, but active queued job still exists -> no duplicate job created, last_scheduled_at updated.
	t2 := t0.Add(11 * time.Minute)
	if _, err := q.EnqueueDueScheduledTargets(ctx, t2); err != nil {
		t.Fatalf("EnqueueDueScheduledTargets(t2) error: %v", err)
	}
	jobs, _ = ListJobs(ctx, pool, &target.ID, "", 10)
	if len(jobs) != 1 {
		t.Fatalf("expected no duplicate job while active queued job exists, got %d", len(jobs))
	}
	updatedTarget, _ = db.GetTarget(ctx, pool, target.ID)
	if updatedTarget.LastScheduledAt == nil || !updatedTarget.LastScheduledAt.UTC().Equal(t2) {
		t.Fatalf("expected LastScheduledAt updated to %v even when active job exists, got %v", t2, updatedTarget.LastScheduledAt)
	}

	// Mark target's queued job succeeded (simulate completed run) so no active job remains.
	if _, err := pool.Exec(ctx, `
		UPDATE backup_jobs
		SET status = 'succeeded', attempts = 1, finished_at = $2, lease_expires_at = NULL
		WHERE id = $1
	`, jobs[0].ID, t2); err != nil {
		t.Fatalf("mark job 1 succeeded error: %v", err)
	}

	// 4. Past next interval with no active job -> 2 concurrent goroutines calling EnqueueDueScheduledTargets
	// must only enqueue 1 new job total (FOR UPDATE SKIP LOCKED).
	t3 := t2.Add(11 * time.Minute)
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		totalEnq int
		errCh   = make(chan error, 2)
		barrier = make(chan struct{})
	)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-barrier
			cnt, err := q.EnqueueDueScheduledTargets(ctx, t3)
			if err != nil {
				errCh <- err
				return
			}
			mu.Lock()
			totalEnq += cnt
			mu.Unlock()
		}()
	}
	close(barrier)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent scheduler error: %v", err)
	}

	jobs, _ = ListJobs(ctx, pool, &target.ID, "", 10)
	if len(jobs) != 2 {
		t.Fatalf("expected exactly 2 total jobs (1 old succeeded + 1 newly scheduled), got %d (totalEnq=%d)", len(jobs), totalEnq)
	}
}

func TestQueue_Integration_StaleJobRecovery(t *testing.T) {
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

	targetName := fmt.Sprintf("stale-target-%d", time.Now().UnixNano())
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

	baseNow := time.Now().UTC().Truncate(time.Second)

	// Job 1: running, attempts=1 < max_attempts=3, lease expired -> should recover to queued
	j1, err := EnqueueJob(ctx, pool, target.ID, 3, baseNow.Add(-time.Hour))
	if err != nil {
		t.Fatalf("EnqueueJob(j1) error: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE backup_jobs
		SET status = 'running', attempts = 1, locked_at = $2, locked_by = 'dead-worker-1', lease_expires_at = $3
		WHERE id = $1
	`, j1.ID, baseNow.Add(-20*time.Minute), baseNow.Add(-10*time.Minute)); err != nil {
		t.Fatalf("seed expired running j1 error: %v", err)
	}

	// Job 2: running, attempts=1 == max_attempts=1, lease expired -> should transition to failed
	j2, err := EnqueueJob(ctx, pool, target.ID, 1, baseNow.Add(-time.Hour))
	if err != nil {
		t.Fatalf("EnqueueJob(j2) error: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE backup_jobs
		SET status = 'running', attempts = 1, locked_at = $2, locked_by = 'dead-worker-2', lease_expires_at = $3
		WHERE id = $1
	`, j2.ID, baseNow.Add(-20*time.Minute), baseNow.Add(-10*time.Minute)); err != nil {
		t.Fatalf("seed expired running j2 error: %v", err)
	}

	// Job 3: claimed via ClaimNextJobWithLease with active future lease -> must have lease set and remain untouched
	j3, err := EnqueueJob(ctx, pool, target.ID, 3, baseNow.Add(-2*time.Hour))
	if err != nil {
		t.Fatalf("EnqueueJob(j3) error: %v", err)
	}
	claimed3, err := ClaimNextJobWithLease(ctx, pool, "live-worker-3", baseNow, 15*time.Minute)
	if err != nil || claimed3 == nil || claimed3.ID != j3.ID {
		t.Fatalf("ClaimNextJobWithLease(j3) = %+v, %v (want job %d)", claimed3, err, j3.ID)
	}
	if claimed3.LeaseExpiresAt == nil || !claimed3.LeaseExpiresAt.UTC().Equal(baseNow.Add(15*time.Minute)) {
		t.Fatalf("expected ClaimNextJobWithLease to set lease_expires_at=%v, got %v", baseNow.Add(15*time.Minute), claimed3.LeaseExpiresAt)
	}

	q := New(pool)
	recovered, err := q.RecoverStaleJobs(ctx, baseNow)
	if err != nil {
		t.Fatalf("RecoverStaleJobs() error: %v", err)
	}
	if recovered < 2 {
		t.Fatalf("RecoverStaleJobs() = %d, want >= 2", recovered)
	}

	got1, _ := GetJob(ctx, pool, j1.ID)
	if got1.Status != StatusQueued || got1.LeaseExpiresAt != nil || got1.ErrorMessage != StaleJobRecoveredError {
		t.Errorf("j1 after recovery = %+v, want queued with nil lease and recovered error message", got1)
	}

	got2, _ := GetJob(ctx, pool, j2.ID)
	if got2.Status != StatusFailed || got2.FinishedAt == nil || got2.LeaseExpiresAt != nil || got2.ErrorMessage != StaleJobMaxAttemptsError {
		t.Errorf("j2 after recovery = %+v, want failed with finished_at, nil lease, and max attempts error message", got2)
	}

	got3, _ := GetJob(ctx, pool, j3.ID)
	if got3.Status != StatusRunning || got3.LeaseExpiresAt == nil || got3.LockedBy != "live-worker-3" {
		t.Errorf("j3 (active lease) should be untouched, got %+v", got3)
	}

	// Verify MarkJobVerifyingWithLease extends lease_expires_at forward
	verifyNow := baseNow.Add(10 * time.Minute)
	if err := MarkJobVerifyingWithLease(ctx, pool, j3.ID, "live-worker-3", verifyNow, 15*time.Minute); err != nil {
		t.Fatalf("MarkJobVerifyingWithLease() error: %v", err)
	}
	got3After, _ := GetJob(ctx, pool, j3.ID)
	if got3After.Status != StatusVerifying {
		t.Fatalf("j3 status = %q, want verifying", got3After.Status)
	}
	if got3After.LeaseExpiresAt == nil || !got3After.LeaseExpiresAt.UTC().Equal(verifyNow.Add(15*time.Minute)) {
		t.Fatalf("j3 LeaseExpiresAt = %v, want extended %v", got3After.LeaseExpiresAt, verifyNow.Add(15*time.Minute))
	}

	// Verify ClaimNextJobWithLease compares run_after against provided `now` (not DB NOW()).
	// First claim the recovered j1 so only jFuture remains queued for this target.
	if _, err := pool.Exec(ctx, "UPDATE backup_jobs SET status = 'succeeded' WHERE id = $1", j1.ID); err != nil {
		t.Fatalf("mark j1 succeeded error: %v", err)
	}
	futureRunAfter := baseNow.Add(2 * time.Hour)
	jFuture, err := EnqueueJob(ctx, pool, target.ID, 3, futureRunAfter)
	if err != nil {
		t.Fatalf("EnqueueJob(jFuture) error: %v", err)
	}
	if claimedTooEarly, err := ClaimNextJobWithLease(ctx, pool, "worker-early", baseNow, 15*time.Minute); err != nil {
		t.Fatalf("ClaimNextJobWithLease(baseNow) error: %v", err)
	} else if claimedTooEarly != nil && claimedTooEarly.ID == jFuture.ID {
		t.Fatalf("ClaimNextJobWithLease(baseNow) claimed future job %d prematurely", jFuture.ID)
	}
	claimedFuture, err := ClaimNextJobWithLease(ctx, pool, "worker-future", futureRunAfter.Add(time.Minute), 15*time.Minute)
	if err != nil || claimedFuture == nil || claimedFuture.ID != jFuture.ID {
		t.Fatalf("ClaimNextJobWithLease(futureNow) = %+v, %v (want job %d)", claimedFuture, err, jFuture.ID)
	}
}
