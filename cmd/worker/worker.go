package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prisandikevin12/pgvault/internal/crypto"
	"github.com/prisandikevin12/pgvault/internal/db"
	"github.com/prisandikevin12/pgvault/internal/notify"
	"github.com/prisandikevin12/pgvault/internal/pgdump"
	"github.com/prisandikevin12/pgvault/internal/queue"
	"github.com/prisandikevin12/pgvault/internal/storage"
	"github.com/prisandikevin12/pgvault/internal/verifier"
)

const (
	defaultPollInterval      = 2 * time.Second
	defaultSchedulerInterval = 15 * time.Second
	defaultJobLeaseDuration  = queue.DefaultJobLeaseDuration
	defaultVerifyTimeout     = 5 * time.Minute
	defaultBaseBackoff       = 15 * time.Second
	defaultMaxBackoff        = 15 * time.Minute
)

// WorkerConfig configures the backup/verification worker runner.
type WorkerConfig struct {
	WorkerID          string
	PollInterval      time.Duration
	SchedulerInterval time.Duration
	PruneInterval     time.Duration
	JobLeaseDuration  time.Duration
	KEK               []byte
	VerifyTimeout     time.Duration
	BaseBackoff       time.Duration
	MaxBackoff        time.Duration
}

// Validate checks required worker settings.
func (c WorkerConfig) Validate() error {
	if len(c.KEK) != crypto.KeySize {
		return fmt.Errorf("worker: KEK must be %d bytes, got %d", crypto.KeySize, len(c.KEK))
	}
	if c.PollInterval < 0 {
		return errors.New("worker: poll interval must be non-negative")
	}
	if c.SchedulerInterval < 0 {
		return errors.New("worker: scheduler interval must be non-negative")
	}
	if c.PruneInterval < 0 {
		return errors.New("worker: prune interval must be non-negative")
	}
	if c.JobLeaseDuration < 0 {
		return errors.New("worker: job lease duration must be non-negative")
	}
	if c.VerifyTimeout < 0 {
		return errors.New("worker: verify timeout must be non-negative")
	}
	return nil
}

// Worker claims backup jobs from PostgreSQL, executes encrypted streaming backups,
// runs isolated Docker restore verification, records artifacts, and sends alerts.
type Worker struct {
	pool     *pgxpool.Pool
	cfg      WorkerConfig
	notifier notify.Notifier // optional; when nil, active alert_channels are loaded from DB
	logger   *slog.Logger
}

// NewWorker validates cfg and builds a Worker instance.
func NewWorker(pool *pgxpool.Pool, cfg WorkerConfig, notifier notify.Notifier, logger *slog.Logger) (*Worker, error) {
	if pool == nil {
		return nil, errors.New("worker: db pool must not be nil")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.WorkerID) == "" {
		host, _ := os.Hostname()
		if host == "" {
			host = "worker"
		}
		cfg.WorkerID = fmt.Sprintf("%s-%d", host, os.Getpid())
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = defaultPollInterval
	}
	if cfg.SchedulerInterval == 0 {
		cfg.SchedulerInterval = defaultSchedulerInterval
	}
	if cfg.PruneInterval == 0 {
		cfg.PruneInterval = cfg.SchedulerInterval
	}
	if cfg.JobLeaseDuration == 0 {
		cfg.JobLeaseDuration = defaultJobLeaseDuration
	}
	if cfg.VerifyTimeout == 0 {
		cfg.VerifyTimeout = defaultVerifyTimeout
	}
	if cfg.BaseBackoff == 0 {
		cfg.BaseBackoff = defaultBaseBackoff
	}
	if cfg.MaxBackoff == 0 {
		cfg.MaxBackoff = defaultMaxBackoff
	}
	if logger == nil {
		logger = slog.Default()
	}

	return &Worker{
		pool:     pool,
		cfg:      cfg,
		notifier: notifier,
		logger:   logger,
	}, nil
}

// RunMaintenanceOnce executes one stale-job recovery and auto-scheduler sweep.
func (w *Worker) RunMaintenanceOnce(ctx context.Context, now time.Time) (recovered int, scheduled int, err error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}

	recovered, err = queue.RecoverStaleJobs(ctx, w.pool, now)
	if err != nil {
		return 0, 0, err
	}
	if recovered > 0 {
		w.logger.Warn("recovered stale backup jobs", "worker_id", w.cfg.WorkerID, "count", recovered)
	}

	scheduled, err = queue.EnqueueDueScheduledTargets(ctx, w.pool, now)
	if err != nil {
		return recovered, 0, err
	}
	if scheduled > 0 {
		w.logger.Info("enqueued scheduled backup jobs", "worker_id", w.cfg.WorkerID, "count", scheduled)
	}
	return recovered, scheduled, nil
}

// RunPruneOnce evaluates retention policies across all targets and deletes expired S3 objects.
func (w *Worker) RunPruneOnce(ctx context.Context, now time.Time) (queue.PruneSummary, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}

	summary, err := queue.PruneExpiredBackups(ctx, w.pool, now, func(delCtx context.Context, target db.BackupTarget) (queue.ObjectDeleter, error) {
		secretKey, decErr := db.UnprotectSecret(w.cfg.KEK, target.StorageSecretKey)
		if decErr != nil {
			return nil, fmt.Errorf("unprotect storage secret: %w", decErr)
		}
		return storage.NewClient(delCtx, storage.Config{
			EndpointURL:     target.StorageEndpoint,
			Region:          target.StorageRegion,
			Bucket:          target.StorageBucket,
			AccessKeyID:     target.StorageAccessKey,
			SecretAccessKey: secretKey,
			ForcePathStyle:  target.StorageForcePathStyle,
		})
	})
	if summary.ObjectsPruned > 0 {
		w.logger.Info("pruned expired backup objects",
			"worker_id", w.cfg.WorkerID,
			"targets_evaluated", summary.TargetsEvaluated,
			"objects_pruned", summary.ObjectsPruned,
			"errors", summary.Errors,
		)
	}
	return summary, err
}

// Run polls the job queue continuously until ctx is canceled, periodically recovering
// stale leases, enqueuing due scheduled backup targets, and pruning expired backups.
func (w *Worker) Run(ctx context.Context) error {
	w.logger.Info("pgvault worker started",
		"worker_id", w.cfg.WorkerID,
		"poll_interval", w.cfg.PollInterval,
		"scheduler_interval", w.cfg.SchedulerInterval,
		"prune_interval", w.cfg.PruneInterval,
		"job_lease_duration", w.cfg.JobLeaseDuration,
	)
	defer w.logger.Info("pgvault worker stopped", "worker_id", w.cfg.WorkerID)

	var (
		lastMaintenance time.Time
		lastPrune       time.Time
	)

	for {
		if ctx.Err() != nil {
			return nil
		}

		now := time.Now().UTC()
		if lastMaintenance.IsZero() || now.Sub(lastMaintenance) >= w.cfg.SchedulerInterval {
			if _, _, err := w.RunMaintenanceOnce(ctx, now); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				w.logger.Error("worker maintenance sweep failed", "worker_id", w.cfg.WorkerID, "error", notify.SanitizeMessage(err.Error()))
			}
			lastMaintenance = now
		}

		if lastPrune.IsZero() || now.Sub(lastPrune) >= w.cfg.PruneInterval {
			if _, err := w.RunPruneOnce(ctx, now); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				w.logger.Error("worker retention prune failed", "worker_id", w.cfg.WorkerID, "error", notify.SanitizeMessage(err.Error()))
			}
			lastPrune = now
		}

		processed, err := w.ProcessOnce(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			w.logger.Error("job processing failed", "worker_id", w.cfg.WorkerID, "error", notify.SanitizeMessage(err.Error()))
		}
		if processed {
			continue
		}

		timer := time.NewTimer(w.cfg.PollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

// ProcessOnce attempts to claim and execute a single queued job with a lease.
// Returns processed=false if no eligible job was available.
func (w *Worker) ProcessOnce(ctx context.Context) (bool, error) {
	job, err := queue.ClaimNextJobWithLease(ctx, w.pool, w.cfg.WorkerID, time.Now().UTC(), w.cfg.JobLeaseDuration)
	if err != nil {
		return false, err
	}
	if job == nil {
		return false, nil
	}
	return true, w.executeJob(ctx, job)
}

func (w *Worker) executeJob(ctx context.Context, job *queue.Job) error {
	w.logger.Info("claimed backup job", "job_id", job.ID, "target_id", job.TargetID, "attempt", job.Attempts, "max_attempts", job.MaxAttempts)

	target, err := db.GetTarget(ctx, w.pool, job.TargetID)
	if err != nil {
		w.handleJobFailure(ctx, job, nil, "", err, false)
		return err
	}

	targetDSN, err := db.UnprotectSecret(w.cfg.KEK, target.TargetDSN)
	if err != nil {
		w.handleJobFailure(ctx, job, target, "", fmt.Errorf("unprotect target DSN: %w", err), false)
		return err
	}
	s3SecretKey, err := db.UnprotectSecret(w.cfg.KEK, target.StorageSecretKey)
	if err != nil {
		w.handleJobFailure(ctx, job, target, "", fmt.Errorf("unprotect storage secret: %w", err), false)
		return err
	}

	s3Client, err := storage.NewClient(ctx, storage.Config{
		EndpointURL:     target.StorageEndpoint,
		Region:          target.StorageRegion,
		Bucket:          target.StorageBucket,
		AccessKeyID:     target.StorageAccessKey,
		SecretAccessKey: s3SecretKey,
		ForcePathStyle:  target.StorageForcePathStyle,
	})
	if err != nil {
		w.handleJobFailure(ctx, job, target, "", fmt.Errorf("init storage client: %w", err), false)
		return err
	}

	majorVer, err := pgdump.DetectMajorVersion(ctx, targetDSN)
	if err != nil {
		w.handleJobFailure(ctx, job, target, "", err, true)
		return err
	}

	objectKey := fmt.Sprintf(
		"backups/%s/%s-job-%d-attempt-%d.pgv1",
		sanitizeKeySegment(target.Name),
		time.Now().UTC().Format("20060102T150405Z"),
		job.ID,
		job.Attempts,
	)

	backupRes, err := pgdump.RunEncryptedBackup(ctx, pgdump.BackupRequest{
		DSN:       targetDSN,
		Storage:   s3Client,
		ObjectKey: objectKey,
		KEK:       w.cfg.KEK,
	})
	if err != nil {
		w.handleJobFailure(ctx, job, target, objectKey, err, true)
		return err
	}

	artifact, err := db.CreateArtifact(ctx, w.pool, db.BackupArtifact{
		JobID:            job.ID,
		TargetID:         target.ID,
		ObjectKey:        backupRes.ObjectKey,
		WrappedDEK:       backupRes.WrappedDEK,
		PlaintextBytes:   backupRes.PlaintextBytes,
		CiphertextBytes:  backupRes.CiphertextBytes,
		CiphertextSHA256: backupRes.CiphertextSHA256,
		PGMajorVersion:   majorVer,
		Tables:           backupRes.Tables,
	})
	if err != nil {
		w.handleJobFailure(ctx, job, target, objectKey, err, true)
		return err
	}

	if err := queue.MarkJobVerifying(ctx, w.pool, job.ID, w.cfg.WorkerID); err != nil {
		w.handleJobFailure(ctx, job, target, objectKey, err, true)
		return err
	}

	verifyRes, verifyErr := verifier.RunVerification(ctx, verifier.VerifyRequest{
		Storage:        s3Client,
		ObjectKey:      backupRes.ObjectKey,
		WrappedDEK:     backupRes.WrappedDEK,
		KEK:            w.cfg.KEK,
		ExpectedTables: backupRes.Tables,
		SanityQuery:    target.SanityQuery,
		PGMajorVersion: majorVer,
		Timeout:        w.cfg.VerifyTimeout,
	})

	var (
		verPassed   bool
		verDurMs    int64
		verTables   int
		verErrClean string
	)
	if verifyRes != nil {
		verPassed = verifyRes.Passed
		verDurMs = verifyRes.RestoreDurationMs
		verTables = verifyRes.RestoredTables
		verErrClean = notify.SanitizeMessage(verifyRes.Error)
	}
	if verifyErr != nil && verErrClean == "" {
		verErrClean = notify.SanitizeMessage(verifyErr.Error())
	}

	if updateErr := db.UpdateArtifactVerification(ctx, w.pool, artifact.ID, verPassed, verDurMs, verErrClean); updateErr != nil {
		w.logger.Error("failed to update artifact verification status", "artifact_id", artifact.ID, "error", updateErr)
	}

	if verifyErr != nil || !verPassed {
		if verifyErr == nil {
			verifyErr = errors.New("restore verification did not pass")
		}
		w.handleJobFailure(ctx, job, target, objectKey, verifyErr, true)
		return verifyErr
	}

	if err := queue.MarkJobSucceeded(ctx, w.pool, job.ID, w.cfg.WorkerID); err != nil {
		w.logger.Error("failed to mark job succeeded", "job_id", job.ID, "error", err)
		return err
	}

	w.dispatchAlert(ctx, target, notify.Event{
		Type:               notify.EventBackupSucceeded,
		TargetName:         target.Name,
		JobID:              job.ID,
		ObjectKey:          backupRes.ObjectKey,
		PlaintextBytes:     backupRes.PlaintextBytes,
		CiphertextBytes:    backupRes.CiphertextBytes,
		RestoreDurationMs:  verDurMs,
		RestoredTables:     verTables,
		VerificationPassed: true,
		Timestamp:          time.Now().UTC(),
	})

	w.logger.Info("backup job succeeded",
		"job_id", job.ID,
		"target", target.Name,
		"object_key", backupRes.ObjectKey,
		"restore_ms", verDurMs,
	)
	return nil
}

func (w *Worker) handleJobFailure(ctx context.Context, job *queue.Job, target *db.BackupTarget, objectKey string, cause error, retryable bool) {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	backoff := queue.ComputeBackoff(job.Attempts, w.cfg.BaseBackoff, w.cfg.MaxBackoff)
	status, err := queue.RequeueOrFailJob(cleanupCtx, w.pool, job.ID, w.cfg.WorkerID, cause, retryable, backoff)
	if err != nil {
		w.logger.Error("failed to update failed job state", "job_id", job.ID, "error", err)
		return
	}

	if status == queue.StatusFailed {
		targetName := fmt.Sprintf("target-%d", job.TargetID)
		if target != nil && target.Name != "" {
			targetName = target.Name
		}
		w.dispatchAlert(cleanupCtx, target, notify.Event{
			Type:         notify.EventBackupFailed,
			TargetName:   targetName,
			JobID:        job.ID,
			ObjectKey:    objectKey,
			ErrorMessage: notify.SanitizeMessage(cause.Error()),
			Timestamp:    time.Now().UTC(),
		})
	}
}

func (w *Worker) dispatchAlert(ctx context.Context, target *db.BackupTarget, event notify.Event) {
	if w.notifier != nil {
		if err := w.notifier.Notify(ctx, event); err != nil {
			w.logger.Warn("alert dispatch failed", "job_id", event.JobID, "error", notify.SanitizeMessage(err.Error()))
		}
		return
	}

	var targetID int64
	if target != nil {
		targetID = target.ID
	}
	channels, err := db.ListActiveAlertChannels(ctx, w.pool, targetID)
	if err != nil {
		w.logger.Warn("failed to load alert channels", "job_id", event.JobID, "error", err)
		return
	}

	for _, ch := range channels {
		if event.Type == notify.EventBackupSucceeded && !ch.NotifyOnSuccess {
			continue
		}
		if event.Type == notify.EventBackupFailed && !ch.NotifyOnFailure {
			continue
		}
		if ch.ChannelType != "telegram" {
			continue
		}

		token, err := db.UnprotectSecret(w.cfg.KEK, ch.BotToken)
		if err != nil {
			w.logger.Warn("failed to decrypt alert channel token", "channel_id", ch.ID, "error", err)
			continue
		}
		tg, err := notify.NewTelegramNotifier(token, ch.ChatID)
		if err != nil {
			w.logger.Warn("invalid telegram alert channel config", "channel_id", ch.ID, "error", err)
			continue
		}
		if err := tg.Notify(ctx, event); err != nil {
			w.logger.Warn("telegram alert failed", "channel_id", ch.ID, "job_id", event.JobID, "error", notify.SanitizeMessage(err.Error()))
		}
	}
}

func sanitizeKeySegment(s string) string {
	var b strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			lastDash = false
		} else if !lastDash && b.Len() > 0 {
			b.WriteByte('-')
			lastDash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "target"
	}
	return out
}
