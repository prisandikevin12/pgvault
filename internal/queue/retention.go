package queue

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prisandikevin12/pgvault/internal/db"
	"github.com/prisandikevin12/pgvault/internal/storage"
)

// RetentionPolicy configures backup retention per target.
// Zero values disable the corresponding rule; when both are 0, nothing is pruned.
type RetentionPolicy struct {
	KeepLast   int
	MaxAgeDays int
}

// RetentionCandidate represents a backup job and its artifact evaluated for retention pruning.
type RetentionCandidate struct {
	ArtifactID int64
	JobID      int64
	TargetID   int64
	JobStatus  string
	ObjectKey  string
	CreatedAt  time.Time
	PrunedAt   *time.Time
}

// ObjectDeleter abstracts S3 object deletion (satisfied by *storage.Client).
type ObjectDeleter interface {
	DeleteObject(ctx context.Context, key string) error
}

// TargetDeleterFactory builds an ObjectDeleter for a given BackupTarget.
type TargetDeleterFactory func(ctx context.Context, target db.BackupTarget) (ObjectDeleter, error)

// PruneSummary summarizes one PruneExpiredBackups pass.
type PruneSummary struct {
	TargetsEvaluated int
	ObjectsPruned    int
	Errors           int
}

// SelectExpiredBackupJobs evaluates retention rules purely and returns the subset of
// candidates eligible for pruning. Only succeeded jobs with a non-empty ObjectKey
// and nil PrunedAt are ever considered; active/failed jobs are never pruned.
func SelectExpiredBackupJobs(candidates []RetentionCandidate, policy RetentionPolicy, now time.Time) []RetentionCandidate {
	if policy.KeepLast <= 0 && policy.MaxAgeDays <= 0 {
		return nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	eligible := make([]RetentionCandidate, 0, len(candidates))
	for _, c := range candidates {
		if c.JobStatus != StatusSucceeded {
			continue
		}
		if c.PrunedAt != nil {
			continue
		}
		if strings.TrimSpace(c.ObjectKey) == "" {
			continue
		}
		eligible = append(eligible, c)
	}
	if len(eligible) == 0 {
		return nil
	}

	// Sort newest-first: CreatedAt DESC, JobID DESC, ArtifactID DESC.
	sort.Slice(eligible, func(i, j int) bool {
		if !eligible[i].CreatedAt.Equal(eligible[j].CreatedAt) {
			return eligible[i].CreatedAt.After(eligible[j].CreatedAt)
		}
		if eligible[i].JobID != eligible[j].JobID {
			return eligible[i].JobID > eligible[j].JobID
		}
		return eligible[i].ArtifactID > eligible[j].ArtifactID
	})

	var cutoff time.Time
	if policy.MaxAgeDays > 0 {
		cutoff = now.Add(-time.Duration(policy.MaxAgeDays) * 24 * time.Hour)
	}

	var expired []RetentionCandidate
	for i, c := range eligible {
		expiredByCount := policy.KeepLast > 0 && i >= policy.KeepLast
		expiredByAge := policy.MaxAgeDays > 0 && !c.CreatedAt.After(cutoff)
		if expiredByCount || expiredByAge {
			expired = append(expired, c)
		}
	}
	return expired
}

// PruneExpiredBackups evaluates retention policies across all configured targets,
// deletes expired objects from S3 first (ignoring NoSuchKey/404), and marks
// backup_artifacts.pruned_at consistently in PostgreSQL.
func (q *Queue) PruneExpiredBackups(ctx context.Context, now time.Time, deleterFactory TargetDeleterFactory) (PruneSummary, error) {
	if q == nil {
		return PruneSummary{}, errors.New("queue: queue must not be nil")
	}
	return PruneExpiredBackups(ctx, q.pool, now, deleterFactory)
}

// PruneExpiredBackups evaluates retention policies for all targets with retention rules enabled.
func PruneExpiredBackups(
	ctx context.Context,
	pool *pgxpool.Pool,
	now time.Time,
	deleterFactory TargetDeleterFactory,
) (PruneSummary, error) {
	if pool == nil {
		return PruneSummary{}, errors.New("queue: pool must not be nil")
	}
	if deleterFactory == nil {
		return PruneSummary{}, errors.New("queue: deleterFactory must not be nil")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	targets, err := db.ListTargets(ctx, pool)
	if err != nil {
		return PruneSummary{}, fmt.Errorf("queue: list targets for retention: %w", err)
	}

	var (
		summary PruneSummary
		errs    []error
	)

	for _, target := range targets {
		policy := RetentionPolicy{
			KeepLast:   target.RetentionKeepLast,
			MaxAgeDays: target.RetentionMaxAgeDays,
		}
		if policy.KeepLast <= 0 && policy.MaxAgeDays <= 0 {
			continue
		}
		summary.TargetsEvaluated++

		candidates, err := listTargetRetentionCandidates(ctx, pool, target.ID)
		if err != nil {
			summary.Errors++
			errs = append(errs, fmt.Errorf("target %d (%s): %w", target.ID, target.Name, err))
			continue
		}

		expired := SelectExpiredBackupJobs(candidates, policy, now)
		if len(expired) == 0 {
			continue
		}

		deleter, err := deleterFactory(ctx, target)
		if err != nil {
			summary.Errors++
			errs = append(errs, fmt.Errorf("target %d (%s) init deleter: %w", target.ID, target.Name, err))
			continue
		}

		for _, cand := range expired {
			if err := deleter.DeleteObject(ctx, cand.ObjectKey); err != nil && !storage.IsNotFoundError(err) {
				summary.Errors++
				errs = append(errs, fmt.Errorf("target %d delete object %q: %w", target.ID, cand.ObjectKey, err))
				continue
			}

			if err := db.MarkArtifactPruned(ctx, pool, cand.ArtifactID, now); err != nil {
				summary.Errors++
				errs = append(errs, fmt.Errorf("target %d mark artifact %d pruned: %w", target.ID, cand.ArtifactID, err))
				continue
			}
			summary.ObjectsPruned++
		}
	}

	return summary, errors.Join(errs...)
}

func listTargetRetentionCandidates(ctx context.Context, pool *pgxpool.Pool, targetID int64) ([]RetentionCandidate, error) {
	rows, err := pool.Query(ctx, `
		SELECT a.id, a.job_id, a.target_id, j.status, a.object_key, a.created_at, a.pruned_at
		FROM backup_artifacts a
		JOIN backup_jobs j ON j.id = a.job_id
		WHERE a.target_id = $1
		  AND a.pruned_at IS NULL
		  AND j.status = 'succeeded'
		ORDER BY a.created_at DESC, a.job_id DESC, a.id DESC
	`, targetID)
	if err != nil {
		return nil, fmt.Errorf("query retention candidates: %w", err)
	}
	defer rows.Close()

	var candidates []RetentionCandidate
	for rows.Next() {
		var c RetentionCandidate
		if err := rows.Scan(&c.ArtifactID, &c.JobID, &c.TargetID, &c.JobStatus, &c.ObjectKey, &c.CreatedAt, &c.PrunedAt); err != nil {
			return nil, fmt.Errorf("scan retention candidate: %w", err)
		}
		candidates = append(candidates, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate retention candidates: %w", err)
	}
	return candidates, nil
}
