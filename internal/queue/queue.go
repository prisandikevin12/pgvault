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

	defaultMaxAttempts = 3
	defaultBaseBackoff = 15 * time.Second
	defaultMaxBackoff  = 15 * time.Minute
)

// Job represents a single row in backup_jobs.
type Job struct {
	ID           int64
	TargetID     int64
	Status       string
	Attempts     int
	MaxAttempts  int
	RunAfter     time.Time
	LockedAt     *time.Time
	LockedBy     string
	StartedAt    *time.Time
	FinishedAt   *time.Time
	ErrorMessage string
	CreatedAt    time.Time
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
			locked_at, COALESCE(locked_by, ''), started_at, finished_at, error_message, created_at
	`, targetID, StatusQueued, maxAttempts, runAfter).Scan(
		&job.ID, &job.TargetID, &job.Status, &job.Attempts, &job.MaxAttempts, &job.RunAfter,
		&job.LockedAt, &job.LockedBy, &job.StartedAt, &job.FinishedAt, &job.ErrorMessage, &job.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("queue: enqueue job: %w", err)
	}
	return &job, nil
}

// ClaimNextJob atomically claims one ready queued job using FOR UPDATE SKIP LOCKED,
// transitions it to running, increments attempts, and records lock metadata.
// Returns (nil, nil) if no eligible job is currently available.
func ClaimNextJob(ctx context.Context, pool *pgxpool.Pool, workerID string) (*Job, error) {
	if pool == nil {
		return nil, errors.New("queue: pool must not be nil")
	}
	if strings.TrimSpace(workerID) == "" {
		return nil, errors.New("queue: workerID is required")
	}

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
			  AND run_after <= NOW()
			ORDER BY run_after ASC, id ASC
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		)
		UPDATE backup_jobs j
		SET status = 'running',
			attempts = j.attempts + 1,
			locked_at = NOW(),
			locked_by = $1,
			started_at = COALESCE(j.started_at, NOW()),
			error_message = ''
		FROM next_job
		WHERE j.id = next_job.id
		RETURNING j.id, j.target_id, j.status, j.attempts, j.max_attempts, j.run_after,
			j.locked_at, COALESCE(j.locked_by, ''), j.started_at, j.finished_at, j.error_message, j.created_at
	`, workerID).Scan(
		&job.ID, &job.TargetID, &job.Status, &job.Attempts, &job.MaxAttempts, &job.RunAfter,
		&job.LockedAt, &job.LockedBy, &job.StartedAt, &job.FinishedAt, &job.ErrorMessage, &job.CreatedAt,
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

// MarkJobVerifying transitions a running job owned by workerID to verifying.
func MarkJobVerifying(ctx context.Context, pool *pgxpool.Pool, jobID int64, workerID string) error {
	tag, err := pool.Exec(ctx, `
		UPDATE backup_jobs
		SET status = 'verifying'
		WHERE id = $1 AND status = 'running' AND locked_by = $2
	`, jobID, workerID)
	if err != nil {
		return fmt.Errorf("queue: mark job %d verifying: %w", jobID, err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("queue: job %d cannot transition to verifying for worker %q", jobID, workerID)
	}
	return nil
}

// MarkJobSucceeded transitions a verifying job owned by workerID to succeeded.
func MarkJobSucceeded(ctx context.Context, pool *pgxpool.Pool, jobID int64, workerID string) error {
	tag, err := pool.Exec(ctx, `
		UPDATE backup_jobs
		SET status = 'succeeded',
			finished_at = NOW(),
			locked_at = NULL,
			locked_by = NULL,
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
// or transitions it permanently to failed. Returns the resulting job status.
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
			locked_at, COALESCE(locked_by, ''), started_at, finished_at, error_message, created_at
		FROM backup_jobs
		WHERE id = $1
	`, jobID).Scan(
		&job.ID, &job.TargetID, &job.Status, &job.Attempts, &job.MaxAttempts, &job.RunAfter,
		&job.LockedAt, &job.LockedBy, &job.StartedAt, &job.FinishedAt, &job.ErrorMessage, &job.CreatedAt,
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
			locked_at, COALESCE(locked_by, ''), started_at, finished_at, error_message, created_at
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
			&job.LockedAt, &job.LockedBy, &job.StartedAt, &job.FinishedAt, &job.ErrorMessage, &job.CreatedAt,
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
