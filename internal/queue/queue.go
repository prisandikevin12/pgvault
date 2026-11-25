package queue

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prisandikevin12/pgvault/internal/notify"
)

const (
	StatusQueued    = "queued"
	StatusRunning   = "running"
	StatusVerifying = "verifying"
	StatusSucceeded = "succeeded"
	StatusFailed    = "failed"

	DefaultJobLeaseDuration  = 15 * time.Minute
	StaleJobRecoveredError   = "worker lease expired (stale job recovered)"
	StaleJobMaxAttemptsError = "worker lease expired (max attempts reached)"

	defaultMaxAttempts = 3
	defaultBaseBackoff = 15 * time.Second
	defaultMaxBackoff  = 15 * time.Minute
)

// Job represents a single row in backup_jobs.
type Job struct {
	ID             int64
	TargetID       int64
	Status         string
	Attempts       int
	MaxAttempts    int
	RunAfter       time.Time
	LockedAt       *time.Time
	LockedBy       string
	LeaseExpiresAt *time.Time
	StartedAt      *time.Time
	FinishedAt     *time.Time
	ErrorMessage   string
	CreatedAt      time.Time
}

// Queue provides pool-backed methods for scheduling, claiming, and recovering backup jobs.
type Queue struct {
	pool *pgxpool.Pool
}

// New constructs a Queue backed by pool.
func New(pool *pgxpool.Pool) *Queue {
	return &Queue{pool: pool}
}

// EnqueueDueScheduledTargets enqueues queued jobs for due targets using FOR UPDATE SKIP LOCKED.
func (q *Queue) EnqueueDueScheduledTargets(ctx context.Context, now time.Time) (int, error) {
	if q == nil {
		return 0, errors.New("queue: queue must not be nil")
	}
	return EnqueueDueScheduledTargets(ctx, q.pool, now)
}

// RecoverStaleJobs recovers running/verifying jobs whose worker leases have expired.
func (q *Queue) RecoverStaleJobs(ctx context.Context, now time.Time) (int, error) {
	if q == nil {
		return 0, errors.New("queue: queue must not be nil")
	}
	return RecoverStaleJobs(ctx, q.pool, now)
}

// ClaimNextJob claims the next ready queued job and sets a lease expiring after leaseDuration.
func (q *Queue) ClaimNextJob(ctx context.Context, workerID string, leaseDuration time.Duration) (*Job, error) {
	if q == nil {
		return nil, errors.New("queue: queue must not be nil")
	}
	return ClaimNextJobWithLease(ctx, q.pool, workerID, time.Now().UTC(), leaseDuration)
}

var allowedTransitions = map[string]map[string]bool{
	StatusQueued: {
		StatusRunning: true,
	},
	StatusRunning: {
		StatusVerifying: true,
		StatusQueued:    true,
		StatusFailed:    true,
	},
	StatusVerifying: {
		StatusSucceeded: true,
		StatusQueued:    true,
		StatusFailed:    true,
	},
}

// ValidateTransition verifies whether moving a job from status `from` to `to` is valid.
func ValidateTransition(from, to string) error {
	targets, ok := allowedTransitions[from]
	if !ok || !targets[to] {
		return fmt.Errorf("queue: invalid job transition %q -> %q", from, to)
	}
	return nil
}

// ComputeBackoff calculates exponential retry backoff capped at maxDelay.
func ComputeBackoff(attempts int, baseDelay, maxDelay time.Duration) time.Duration {
	if baseDelay <= 0 {
		baseDelay = defaultBaseBackoff
	}
	if maxDelay <= 0 {
		maxDelay = defaultMaxBackoff
	}
	if attempts <= 1 {
		if baseDelay > maxDelay {
			return maxDelay
		}
		return baseDelay
	}

	delay := baseDelay
	for i := 1; i < attempts; i++ {
		if delay >= maxDelay/2 {
			return maxDelay
		}
		delay *= 2
	}
	if delay > maxDelay {
		return maxDelay
	}
	return delay
}

// DecideFailureDisposition returns StatusQueued if the job should be retried, or StatusFailed otherwise.
func DecideFailureDisposition(attempts, maxAttempts int, retryable bool) string {
	if retryable && attempts < maxAttempts {
		return StatusQueued
	}
	return StatusFailed
}

// IsTargetDue reports whether a target with intervalSeconds should be scheduled at `now`.
func IsTargetDue(lastScheduledAt *time.Time, intervalSeconds int, now time.Time) bool {
	if intervalSeconds <= 0 {
		return false
	}
	if lastScheduledAt == nil {
		return true
	}
	dueAt := lastScheduledAt.Add(time.Duration(intervalSeconds) * time.Second)
	return !dueAt.After(now)
}

// DecideStaleRecovery chooses the target status and diagnostic error for an expired job lease.
func DecideStaleRecovery(attempts, maxAttempts int) (status string, errMsg string) {
	if attempts < maxAttempts {
		return StatusQueued, StaleJobRecoveredError
	}
	return StatusFailed, StaleJobMaxAttemptsError
}

// ComputeLeaseExpiry computes the lease expiration timestamp from `now` and `leaseDuration`.
func ComputeLeaseExpiry(now time.Time, leaseDuration time.Duration) time.Time {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if leaseDuration <= 0 {
		leaseDuration = DefaultJobLeaseDuration
	}
	return now.Add(leaseDuration)
}

// EnqueueJob creates a new queued backup job for targetID.
func EnqueueJob(ctx context.Context, pool *pgxpool.Pool, targetID int64, maxAttempts int, runAfter time.Time) (*Job, error) {
	if pool == nil {
		return nil, errors.New("queue: pool must not be nil")
	}
	if targetID <= 0 {
		return nil, errors.New("queue: targetID must be positive")
	}
	if maxAttempts <= 0 {
		maxAttempts = defaultMaxAttempts
	}
	if runAfter.IsZero() {
		runAfter = time.Now().UTC()
	}

	var job Job
	err := pool.QueryRow(ctx, `
		INSERT INTO backup_jobs (target_id, status, attempts, max_attempts, run_after)
		VALUES ($1, $2, 0, $3, $4)
		RETURNING id, target_id, status, attempts, max_attempts, run_after,
			locked_at, COALESCE(locked_by, ''), lease_expires_at, started_at, finished_at, error_message, created_at
	`, targetID, StatusQueued, maxAttempts, runAfter).Scan(
		&job.ID, &job.TargetID, &job.Status, &job.Attempts, &job.MaxAttempts, &job.RunAfter,
		&job.LockedAt, &job.LockedBy, &job.LeaseExpiresAt, &job.StartedAt, &job.FinishedAt, &job.ErrorMessage, &job.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("queue: enqueue job: %w", err)
	}
	return &job, nil
}

// EnqueueDueScheduledTargets finds targets whose scheduled interval is due using FOR UPDATE SKIP LOCKED,
// skips creating duplicate jobs when a target already has an active job (queued/running/verifying),
// and always updates last_scheduled_at = now for each due target processed.
func EnqueueDueScheduledTargets(ctx context.Context, pool *pgxpool.Pool, now time.Time) (int, error) {
	if pool == nil {
		return 0, errors.New("queue: pool must not be nil")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("queue: begin scheduler tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rows, err := tx.Query(ctx, `
		SELECT id
		FROM backup_targets
		WHERE interval_seconds > 0
		  AND (
			last_scheduled_at IS NULL
			OR last_scheduled_at + (interval_seconds * INTERVAL '1 second') <= $1
		  )
		ORDER BY id ASC
		FOR UPDATE SKIP LOCKED
	`, now)
	if err != nil {
		return 0, fmt.Errorf("queue: select due scheduled targets: %w", err)
	}

	var dueTargetIDs []int64
	for rows.Next() {
		var targetID int64
		if err := rows.Scan(&targetID); err != nil {
			rows.Close()
			return 0, fmt.Errorf("queue: scan due target id: %w", err)
		}
		dueTargetIDs = append(dueTargetIDs, targetID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("queue: iterate due targets: %w", err)
	}
	rows.Close()

	enqueued := 0
	for _, targetID := range dueTargetIDs {
		var hasActiveJob bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1
				FROM backup_jobs
				WHERE target_id = $1
				  AND status IN ('queued', 'running', 'verifying')
			)
		`, targetID).Scan(&hasActiveJob); err != nil {
			return 0, fmt.Errorf("queue: check active job for target %d: %w", targetID, err)
		}

		if _, err := tx.Exec(ctx, `
			UPDATE backup_targets
			SET last_scheduled_at = $2,
				updated_at = NOW()
			WHERE id = $1
		`, targetID, now); err != nil {
			return 0, fmt.Errorf("queue: update last_scheduled_at for target %d: %w", targetID, err)
		}

		if hasActiveJob {
			continue
		}

		if _, err := tx.Exec(ctx, `
			INSERT INTO backup_jobs (target_id, status, attempts, max_attempts, run_after)
			VALUES ($1, 'queued', 0, $2, $3)
		`, targetID, defaultMaxAttempts, now); err != nil {
			return 0, fmt.Errorf("queue: insert scheduled job for target %d: %w", targetID, err)
		}
		enqueued++
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("queue: commit scheduler tx: %w", err)
	}
	return enqueued, nil
}

// ClaimNextJob atomically claims one ready queued job using FOR UPDATE SKIP LOCKED
// with the default 15-minute lease duration.
func ClaimNextJob(ctx context.Context, pool *pgxpool.Pool, workerID string) (*Job, error) {
	return ClaimNextJobWithLease(ctx, pool, workerID, time.Now().UTC(), DefaultJobLeaseDuration)
}

// ClaimNextJobWithLease atomically claims one ready queued job using FOR UPDATE SKIP LOCKED,
// transitions it to running, increments attempts, records lock metadata, and sets lease_expires_at.
// Returns (nil, nil) if no eligible job is currently available.
func ClaimNextJobWithLease(
	ctx context.Context,
	pool *pgxpool.Pool,
	workerID string,
	now time.Time,
	leaseDuration time.Duration,
) (*Job, error) {
	if pool == nil {
		return nil, errors.New("queue: pool must not be nil")
	}
	if strings.TrimSpace(workerID) == "" {
		return nil, errors.New("queue: workerID is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	leaseExpiresAt := ComputeLeaseExpiry(now, leaseDuration)

	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("queue: begin claim tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var job Job
	err = tx.QueryRow(ctx, `
		WITH next_job AS (
			SELECT id
			FROM backup_jobs
			WHERE status = 'queued'
			  AND run_after <= $2
			ORDER BY run_after ASC, id ASC
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		)
		UPDATE backup_jobs j
		SET status = 'running',
			attempts = j.attempts + 1,
			locked_at = $2,
			locked_by = $1,
			lease_expires_at = $3,
			started_at = COALESCE(j.started_at, $2),
			error_message = ''
		FROM next_job
		WHERE j.id = next_job.id
		RETURNING j.id, j.target_id, j.status, j.attempts, j.max_attempts, j.run_after,
			j.locked_at, COALESCE(j.locked_by, ''), j.lease_expires_at, j.started_at, j.finished_at, j.error_message, j.created_at
	`, workerID, now, leaseExpiresAt).Scan(
		&job.ID, &job.TargetID, &job.Status, &job.Attempts, &job.MaxAttempts, &job.RunAfter,
		&job.LockedAt, &job.LockedBy, &job.LeaseExpiresAt, &job.StartedAt, &job.FinishedAt, &job.ErrorMessage, &job.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("queue: claim next job: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("queue: commit claim tx: %w", err)
	}
	return &job, nil
}

// RecoverStaleJobs finds running/verifying jobs whose lease_expires_at <= now using FOR UPDATE SKIP LOCKED,
// requeuing jobs with remaining attempts or permanently failing jobs that reached max_attempts.
func RecoverStaleJobs(ctx context.Context, pool *pgxpool.Pool, now time.Time) (int, error) {
	if pool == nil {
		return 0, errors.New("queue: pool must not be nil")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("queue: begin stale recovery tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	type staleJob struct {
		id          int64
		attempts    int
		maxAttempts int
	}

	rows, err := tx.Query(ctx, `
		SELECT id, attempts, max_attempts
		FROM backup_jobs
		WHERE status IN ('running', 'verifying')
		  AND lease_expires_at IS NOT NULL
		  AND lease_expires_at <= $1
		ORDER BY lease_expires_at ASC, id ASC
		FOR UPDATE SKIP LOCKED
	`, now)
	if err != nil {
		return 0, fmt.Errorf("queue: select stale jobs: %w", err)
	}

	var staleJobs []staleJob
	for rows.Next() {
		var sj staleJob
		if err := rows.Scan(&sj.id, &sj.attempts, &sj.maxAttempts); err != nil {
			rows.Close()
			return 0, fmt.Errorf("queue: scan stale job: %w", err)
		}
		staleJobs = append(staleJobs, sj)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("queue: iterate stale jobs: %w", err)
	}
	rows.Close()

	recovered := 0
	for _, sj := range staleJobs {
		nextStatus, errMsg := DecideStaleRecovery(sj.attempts, sj.maxAttempts)
		if nextStatus == StatusQueued {
			if _, err := tx.Exec(ctx, `
				UPDATE backup_jobs
				SET status = 'queued',
					run_after = $2,
					locked_at = NULL,
					locked_by = NULL,
					lease_expires_at = NULL,
					error_message = $3
				WHERE id = $1
			`, sj.id, now, errMsg); err != nil {
				return 0, fmt.Errorf("queue: requeue stale job %d: %w", sj.id, err)
			}
		} else {
			if _, err := tx.Exec(ctx, `
				UPDATE backup_jobs
				SET status = 'failed',
					finished_at = $2,
					locked_at = NULL,
					locked_by = NULL,
					lease_expires_at = NULL,
					error_message = $3
				WHERE id = $1
			`, sj.id, now, errMsg); err != nil {
				return 0, fmt.Errorf("queue: fail stale job %d: %w", sj.id, err)
			}
		}
		recovered++
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("queue: commit stale recovery tx: %w", err)
	}
	return recovered, nil
}

// MarkJobVerifying transitions a running job owned by workerID to verifying
// and refreshes its worker lease using the default lease duration.
func MarkJobVerifying(ctx context.Context, pool *pgxpool.Pool, jobID int64, workerID string) error {
	return MarkJobVerifyingWithLease(ctx, pool, jobID, workerID, time.Now().UTC(), DefaultJobLeaseDuration)
}

// MarkJobVerifyingWithLease transitions a running job owned by workerID to verifying
// and extends lease_expires_at so long dump+verify runs are not prematurely reclaimed.
func MarkJobVerifyingWithLease(
	ctx context.Context,
	pool *pgxpool.Pool,
	jobID int64,
	workerID string,
	now time.Time,
	leaseDuration time.Duration,
) error {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	leaseExpiresAt := ComputeLeaseExpiry(now, leaseDuration)
	tag, err := pool.Exec(ctx, `
		UPDATE backup_jobs
		SET status = 'verifying',
			lease_expires_at = $3
		WHERE id = $1 AND status = 'running' AND locked_by = $2
	`, jobID, workerID, leaseExpiresAt)
	if err != nil {
		return fmt.Errorf("queue: mark job %d verifying: %w", jobID, err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("queue: job %d cannot transition to verifying for worker %q", jobID, workerID)
	}
	return nil
}

// MarkJobSucceeded transitions a verifying job owned by workerID to succeeded and clears its lease.
func MarkJobSucceeded(ctx context.Context, pool *pgxpool.Pool, jobID int64, workerID string) error {
	tag, err := pool.Exec(ctx, `
		UPDATE backup_jobs
		SET status = 'succeeded',
			finished_at = NOW(),
			locked_at = NULL,
			locked_by = NULL,
			lease_expires_at = NULL,
			error_message = ''
		WHERE id = $1 AND status = 'verifying' AND locked_by = $2
	`, jobID, workerID)
	if err != nil {
		return fmt.Errorf("queue: mark job %d succeeded: %w", jobID, err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("queue: job %d cannot transition to succeeded for worker %q", jobID, workerID)
	}
	return nil
}

// RequeueOrFailJob either requeues a failed job with backoff (if retryable && attempts < max_attempts)
// or transitions it permanently to failed, clearing its worker lease. Returns the resulting job status.
func RequeueOrFailJob(
	ctx context.Context,
	pool *pgxpool.Pool,
	jobID int64,
	workerID string,
	cause error,
	retryable bool,
	backoff time.Duration,
) (string, error) {
	if pool == nil {
		return "", errors.New("queue: pool must not be nil")
	}

	errMsg := ""
	if cause != nil {
		errMsg = notify.SanitizeMessage(cause.Error())
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("queue: begin requeue/fail tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var (
		currentStatus string
		attempts      int
		maxAttempts   int
		lockedBy      string
	)
	err = tx.QueryRow(ctx, `
		SELECT status, attempts, max_attempts, COALESCE(locked_by, '')
		FROM backup_jobs
		WHERE id = $1
		FOR UPDATE
	`, jobID).Scan(&currentStatus, &attempts, &maxAttempts, &lockedBy)
	if err != nil {
		return "", fmt.Errorf("queue: lock job %d for requeue/fail: %w", jobID, err)
	}
	if workerID != "" && lockedBy != "" && lockedBy != workerID {
		return "", fmt.Errorf("queue: job %d is locked by %q, not %q", jobID, lockedBy, workerID)
	}

	nextStatus := DecideFailureDisposition(attempts, maxAttempts, retryable)
	if err := ValidateTransition(currentStatus, nextStatus); err != nil {
		return "", err
	}

	if nextStatus == StatusQueued {
		if backoff <= 0 {
			backoff = ComputeBackoff(attempts, defaultBaseBackoff, defaultMaxBackoff)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE backup_jobs
			SET status = 'queued',
				run_after = NOW() + ($2 * INTERVAL '1 millisecond'),
				locked_at = NULL,
				locked_by = NULL,
				lease_expires_at = NULL,
				error_message = $3
			WHERE id = $1
		`, jobID, backoff.Milliseconds(), errMsg); err != nil {
			return "", fmt.Errorf("queue: requeue job %d: %w", jobID, err)
		}
	} else {
		if _, err := tx.Exec(ctx, `
			UPDATE backup_jobs
			SET status = 'failed',
				finished_at = NOW(),
				locked_at = NULL,
				locked_by = NULL,
				lease_expires_at = NULL,
				error_message = $2
			WHERE id = $1
		`, jobID, errMsg); err != nil {
			return "", fmt.Errorf("queue: fail job %d: %w", jobID, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("queue: commit requeue/fail tx: %w", err)
	}
	return nextStatus, nil
}

// GetJob retrieves a job by ID.
func GetJob(ctx context.Context, pool *pgxpool.Pool, jobID int64) (*Job, error) {
	var job Job
	err := pool.QueryRow(ctx, `
		SELECT id, target_id, status, attempts, max_attempts, run_after,
			locked_at, COALESCE(locked_by, ''), lease_expires_at, started_at, finished_at, error_message, created_at
		FROM backup_jobs
		WHERE id = $1
	`, jobID).Scan(
		&job.ID, &job.TargetID, &job.Status, &job.Attempts, &job.MaxAttempts, &job.RunAfter,
		&job.LockedAt, &job.LockedBy, &job.LeaseExpiresAt, &job.StartedAt, &job.FinishedAt, &job.ErrorMessage, &job.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("queue: get job %d: %w", jobID, err)
	}
	return &job, nil
}

// ListJobs returns backup jobs optionally filtered by targetID and/or status, ordered newest first.
func ListJobs(ctx context.Context, pool *pgxpool.Pool, targetID *int64, status string, limit int) ([]Job, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	var (
		clauses []string
		args    []any
		argIdx  = 1
	)
	if targetID != nil {
		clauses = append(clauses, fmt.Sprintf("target_id = $%d", argIdx))
		args = append(args, *targetID)
		argIdx++
	}
	if strings.TrimSpace(status) != "" {
		clauses = append(clauses, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, strings.TrimSpace(status))
		argIdx++
	}

	query := `
		SELECT id, target_id, status, attempts, max_attempts, run_after,
			locked_at, COALESCE(locked_by, ''), lease_expires_at, started_at, finished_at, error_message, created_at
		FROM backup_jobs
	`
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += fmt.Sprintf(" ORDER BY created_at DESC, id DESC LIMIT $%d", argIdx)
	args = append(args, limit)

	rows, err := pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("queue: list jobs: %w", err)
	}
	defer rows.Close()

	jobs := make([]Job, 0)
	for rows.Next() {
		var job Job
		if err := rows.Scan(
			&job.ID, &job.TargetID, &job.Status, &job.Attempts, &job.MaxAttempts, &job.RunAfter,
			&job.LockedAt, &job.LockedBy, &job.LeaseExpiresAt, &job.StartedAt, &job.FinishedAt, &job.ErrorMessage, &job.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("queue: scan job: %w", err)
		}
		jobs = append(jobs, job)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("queue: iterate jobs: %w", err)
	}
	return jobs, nil
}
