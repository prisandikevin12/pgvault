package db

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prisandikevin12/pgvault/internal/crypto"
	"github.com/prisandikevin12/pgvault/internal/pgdump"
	"github.com/prisandikevin12/pgvault/migrations"
)

const (
	secretPrefix     = "enc:v1:"
	secretNonceSize  = 12
	migrationLockKey = int64(72839104721)
)

// BackupTarget represents a configured PostgreSQL database and destination S3 storage.
type BackupTarget struct {
	ID                    int64
	Name                  string
	TargetDSN             string
	StorageEndpoint       string
	StorageRegion         string
	StorageBucket         string
	StorageAccessKey      string
	StorageSecretKey      string
	StorageForcePathStyle bool
	SanityQuery           string
	ScheduleCron          string
	IntervalSeconds       int
	RetentionKeepLast     int
	RetentionMaxAgeDays   int
	LastScheduledAt       *time.Time
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

// BackupArtifact represents an encrypted backup object stored in S3 and its verification outcome.
type BackupArtifact struct {
	ID                 int64
	JobID              int64
	TargetID           int64
	ObjectKey          string
	WrappedDEK         []byte
	PlaintextBytes     int64
	CiphertextBytes    int64
	CiphertextSHA256   string
	PGMajorVersion     int
	Tables             []pgdump.TableSnapshot
	VerificationPassed bool
	RestoreDurationMs  int64
	VerificationError  string
	PrunedAt           *time.Time
	CreatedAt          time.Time
}

// AlertChannel represents an alerting destination (global if TargetID == nil, or per-target).
type AlertChannel struct {
	ID              int64
	TargetID        *int64
	ChannelType     string
	BotToken        string
	ChatID          string
	NotifyOnFailure bool
	NotifyOnSuccess bool
	Enabled         bool
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// ConnectPool creates and pings a pgxpool.Pool for the application database.
func ConnectPool(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, errors.New("db: DSN is required")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("db: create pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db: ping database: %w", err)
	}
	return pool, nil
}

// ApplyMigrations runs all embedded SQL migrations idempotently under an advisory lock.
func ApplyMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return errors.New("db: pool must not be nil")
	}

	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		return fmt.Errorf("db: read embedded migrations: %w", err)
	}

	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("db: begin migration tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", migrationLockKey); err != nil {
		return fmt.Errorf("db: acquire migration lock: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`); err != nil {
		return fmt.Errorf("db: ensure schema_migrations table: %w", err)
	}

	for _, name := range files {
		var applied bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)", name).Scan(&applied); err != nil {
			return fmt.Errorf("db: check migration %s: %w", name, err)
		}
		if applied {
			continue
		}

		rawSQL, err := fs.ReadFile(migrations.FS, name)
		if err != nil {
			return fmt.Errorf("db: read migration %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, string(rawSQL)); err != nil {
			return fmt.Errorf("db: execute migration %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", name); err != nil {
			return fmt.Errorf("db: record migration %s: %w", name, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("db: commit migrations: %w", err)
	}
	return nil
}

// ProtectSecret encrypts a sensitive string (e.g. target DSN or S3 secret key) with AES-256-GCM
// using a 32-byte KEK, returning an "enc:v1:<base64>" encoded payload.
func ProtectSecret(kek []byte, plaintext string) (string, error) {
	if len(kek) != crypto.KeySize {
		return "", fmt.Errorf("db: %w", crypto.ErrInvalidKeySize)
	}
	if plaintext == "" {
		return "", nil
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return "", fmt.Errorf("db: create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("db: create GCM: %w", err)
	}

	nonce := make([]byte, secretNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("db: generate secret nonce: %w", err)
	}
	sealed := aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return secretPrefix + base64.StdEncoding.EncodeToString(sealed), nil
}

// UnprotectSecret decrypts an "enc:v1:<base64>" payload using the 32-byte KEK.
// Unprefixed strings are returned as-is for development/migration convenience.
func UnprotectSecret(kek []byte, stored string) (string, error) {
	if stored == "" || !strings.HasPrefix(stored, secretPrefix) {
		return stored, nil
	}
	if len(kek) != crypto.KeySize {
		return "", fmt.Errorf("db: %w", crypto.ErrInvalidKeySize)
	}

	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, secretPrefix))
	if err != nil {
		return "", fmt.Errorf("db: decode protected secret: %w", err)
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return "", fmt.Errorf("db: create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("db: create GCM: %w", err)
	}
	if len(raw) < secretNonceSize+aead.Overhead() {
		return "", errors.New("db: protected secret truncated")
	}

	pt, err := aead.Open(nil, raw[:secretNonceSize], raw[secretNonceSize:], nil)
	if err != nil {
		return "", fmt.Errorf("db: decrypt protected secret: %w", err)
	}
	return string(pt), nil
}

// CreateTarget inserts a new backup target row.
func CreateTarget(ctx context.Context, pool *pgxpool.Pool, t BackupTarget) (*BackupTarget, error) {
	if t.IntervalSeconds <= 0 {
		t.IntervalSeconds = 86400
	}
	if t.RetentionKeepLast < 0 || t.RetentionMaxAgeDays < 0 {
		return nil, errors.New("db: retention policy values must be non-negative")
	}

	var out BackupTarget
	err := pool.QueryRow(ctx, `
		INSERT INTO backup_targets (
			name, target_dsn, storage_endpoint, storage_region, storage_bucket,
			storage_access_key, storage_secret_key, storage_force_path_style,
			sanity_query, schedule_cron, interval_seconds,
			retention_keep_last, retention_max_age_days
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		RETURNING id, name, target_dsn, storage_endpoint, storage_region, storage_bucket,
			storage_access_key, storage_secret_key, storage_force_path_style,
			sanity_query, schedule_cron, interval_seconds,
			retention_keep_last, retention_max_age_days, last_scheduled_at, created_at, updated_at
	`,
		t.Name, t.TargetDSN, t.StorageEndpoint, t.StorageRegion, t.StorageBucket,
		t.StorageAccessKey, t.StorageSecretKey, t.StorageForcePathStyle,
		t.SanityQuery, t.ScheduleCron, t.IntervalSeconds,
		t.RetentionKeepLast, t.RetentionMaxAgeDays,
	).Scan(
		&out.ID, &out.Name, &out.TargetDSN, &out.StorageEndpoint, &out.StorageRegion, &out.StorageBucket,
		&out.StorageAccessKey, &out.StorageSecretKey, &out.StorageForcePathStyle,
		&out.SanityQuery, &out.ScheduleCron, &out.IntervalSeconds,
		&out.RetentionKeepLast, &out.RetentionMaxAgeDays, &out.LastScheduledAt, &out.CreatedAt, &out.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("db: create backup target: %w", err)
	}
	return &out, nil
}

// GetTarget fetches a backup target by ID.
func GetTarget(ctx context.Context, pool *pgxpool.Pool, id int64) (*BackupTarget, error) {
	var out BackupTarget
	err := pool.QueryRow(ctx, `
		SELECT id, name, target_dsn, storage_endpoint, storage_region, storage_bucket,
			storage_access_key, storage_secret_key, storage_force_path_style,
			sanity_query, schedule_cron, interval_seconds,
			retention_keep_last, retention_max_age_days, last_scheduled_at, created_at, updated_at
		FROM backup_targets
		WHERE id = $1
	`, id).Scan(
		&out.ID, &out.Name, &out.TargetDSN, &out.StorageEndpoint, &out.StorageRegion, &out.StorageBucket,
		&out.StorageAccessKey, &out.StorageSecretKey, &out.StorageForcePathStyle,
		&out.SanityQuery, &out.ScheduleCron, &out.IntervalSeconds,
		&out.RetentionKeepLast, &out.RetentionMaxAgeDays, &out.LastScheduledAt, &out.CreatedAt, &out.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("db: get backup target %d: %w", id, err)
	}
	return &out, nil
}

// ListTargets returns all backup targets ordered newest first.
func ListTargets(ctx context.Context, pool *pgxpool.Pool) ([]BackupTarget, error) {
	rows, err := pool.Query(ctx, `
		SELECT id, name, target_dsn, storage_endpoint, storage_region, storage_bucket,
			storage_access_key, storage_secret_key, storage_force_path_style,
			sanity_query, schedule_cron, interval_seconds,
			retention_keep_last, retention_max_age_days, last_scheduled_at, created_at, updated_at
		FROM backup_targets
		ORDER BY created_at DESC, id DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("db: list backup targets: %w", err)
	}
	defer rows.Close()

	targets := make([]BackupTarget, 0)
	for rows.Next() {
		var out BackupTarget
		if err := rows.Scan(
			&out.ID, &out.Name, &out.TargetDSN, &out.StorageEndpoint, &out.StorageRegion, &out.StorageBucket,
			&out.StorageAccessKey, &out.StorageSecretKey, &out.StorageForcePathStyle,
			&out.SanityQuery, &out.ScheduleCron, &out.IntervalSeconds,
			&out.RetentionKeepLast, &out.RetentionMaxAgeDays, &out.LastScheduledAt, &out.CreatedAt, &out.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("db: scan backup target: %w", err)
		}
		targets = append(targets, out)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db: iterate backup targets: %w", err)
	}
	return targets, nil
}

// UpdateTarget updates all mutable columns of an existing backup target.
func UpdateTarget(ctx context.Context, pool *pgxpool.Pool, t BackupTarget) (*BackupTarget, error) {
	if t.RetentionKeepLast < 0 || t.RetentionMaxAgeDays < 0 {
		return nil, errors.New("db: retention policy values must be non-negative")
	}
	var out BackupTarget
	err := pool.QueryRow(ctx, `
		UPDATE backup_targets
		SET name = $2,
			target_dsn = $3,
			storage_endpoint = $4,
			storage_region = $5,
			storage_bucket = $6,
			storage_access_key = $7,
			storage_secret_key = $8,
			storage_force_path_style = $9,
			sanity_query = $10,
			schedule_cron = $11,
			interval_seconds = $12,
			retention_keep_last = $13,
			retention_max_age_days = $14,
			updated_at = NOW()
		WHERE id = $1
		RETURNING id, name, target_dsn, storage_endpoint, storage_region, storage_bucket,
			storage_access_key, storage_secret_key, storage_force_path_style,
			sanity_query, schedule_cron, interval_seconds,
			retention_keep_last, retention_max_age_days, last_scheduled_at, created_at, updated_at
	`,
		t.ID, t.Name, t.TargetDSN, t.StorageEndpoint, t.StorageRegion, t.StorageBucket,
		t.StorageAccessKey, t.StorageSecretKey, t.StorageForcePathStyle,
		t.SanityQuery, t.ScheduleCron, t.IntervalSeconds,
		t.RetentionKeepLast, t.RetentionMaxAgeDays,
	).Scan(
		&out.ID, &out.Name, &out.TargetDSN, &out.StorageEndpoint, &out.StorageRegion, &out.StorageBucket,
		&out.StorageAccessKey, &out.StorageSecretKey, &out.StorageForcePathStyle,
		&out.SanityQuery, &out.ScheduleCron, &out.IntervalSeconds,
		&out.RetentionKeepLast, &out.RetentionMaxAgeDays, &out.LastScheduledAt, &out.CreatedAt, &out.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("db: update backup target %d: %w", t.ID, err)
	}
	return &out, nil
}

// DeleteTarget deletes a backup target by ID. Returns true if a row was deleted.
func DeleteTarget(ctx context.Context, pool *pgxpool.Pool, id int64) (bool, error) {
	tag, err := pool.Exec(ctx, "DELETE FROM backup_targets WHERE id = $1", id)
	if err != nil {
		return false, fmt.Errorf("db: delete backup target %d: %w", id, err)
	}
	return tag.RowsAffected() == 1, nil
}

// CreateArtifact inserts a backup_artifacts record for a completed backup upload.
func CreateArtifact(ctx context.Context, pool *pgxpool.Pool, a BackupArtifact) (*BackupArtifact, error) {
	tables := a.Tables
	if tables == nil {
		tables = []pgdump.TableSnapshot{}
	}
	tablesJSON, err := json.Marshal(tables)
	if err != nil {
		return nil, fmt.Errorf("db: marshal tables_json: %w", err)
	}

	var out BackupArtifact
	var rawTables []byte
	err = pool.QueryRow(ctx, `
		INSERT INTO backup_artifacts (
			job_id, target_id, object_key, wrapped_dek, plaintext_bytes,
			ciphertext_bytes, ciphertext_sha256, pg_major_version, tables_json,
			verification_passed, restore_duration_ms, verification_error
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT (job_id) DO UPDATE SET
			object_key = EXCLUDED.object_key,
			wrapped_dek = EXCLUDED.wrapped_dek,
			plaintext_bytes = EXCLUDED.plaintext_bytes,
			ciphertext_bytes = EXCLUDED.ciphertext_bytes,
			ciphertext_sha256 = EXCLUDED.ciphertext_sha256,
			pg_major_version = EXCLUDED.pg_major_version,
			tables_json = EXCLUDED.tables_json,
			verification_passed = EXCLUDED.verification_passed,
			restore_duration_ms = EXCLUDED.restore_duration_ms,
			verification_error = EXCLUDED.verification_error,
			pruned_at = NULL,
			created_at = NOW()
		RETURNING id, job_id, target_id, object_key, wrapped_dek, plaintext_bytes,
			ciphertext_bytes, ciphertext_sha256, pg_major_version, tables_json,
			verification_passed, restore_duration_ms, verification_error, pruned_at, created_at
	`,
		a.JobID, a.TargetID, a.ObjectKey, a.WrappedDEK, a.PlaintextBytes,
		a.CiphertextBytes, a.CiphertextSHA256, a.PGMajorVersion, tablesJSON,
		a.VerificationPassed, a.RestoreDurationMs, a.VerificationError,
	).Scan(
		&out.ID, &out.JobID, &out.TargetID, &out.ObjectKey, &out.WrappedDEK, &out.PlaintextBytes,
		&out.CiphertextBytes, &out.CiphertextSHA256, &out.PGMajorVersion, &rawTables,
		&out.VerificationPassed, &out.RestoreDurationMs, &out.VerificationError, &out.PrunedAt, &out.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("db: create backup artifact: %w", err)
	}
	if err := json.Unmarshal(rawTables, &out.Tables); err != nil {
		return nil, fmt.Errorf("db: unmarshal tables_json: %w", err)
	}
	return &out, nil
}

// UpdateArtifactVerification updates verification telemetry on an existing backup artifact.
func UpdateArtifactVerification(ctx context.Context, pool *pgxpool.Pool, artifactID int64, passed bool, restoreDurationMs int64, verificationErr string) error {
	tag, err := pool.Exec(ctx, `
		UPDATE backup_artifacts
		SET verification_passed = $2,
			restore_duration_ms = $3,
			verification_error = $4
		WHERE id = $1
	`, artifactID, passed, restoreDurationMs, verificationErr)
	if err != nil {
		return fmt.Errorf("db: update artifact %d verification: %w", artifactID, err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("db: artifact %d not found", artifactID)
	}
	return nil
}

// MarkArtifactPruned marks an artifact as pruned from object storage at prunedAt.
func MarkArtifactPruned(ctx context.Context, pool *pgxpool.Pool, artifactID int64, prunedAt time.Time) error {
	if prunedAt.IsZero() {
		prunedAt = time.Now().UTC()
	}
	tag, err := pool.Exec(ctx, `
		UPDATE backup_artifacts
		SET pruned_at = $2
		WHERE id = $1 AND pruned_at IS NULL
	`, artifactID, prunedAt)
	if err != nil {
		return fmt.Errorf("db: mark artifact %d pruned: %w", artifactID, err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("db: artifact %d not found or already pruned", artifactID)
	}
	return nil
}

// GetArtifactByID fetches a backup artifact by its primary ID.
func GetArtifactByID(ctx context.Context, pool *pgxpool.Pool, id int64) (*BackupArtifact, error) {
	var out BackupArtifact
	var rawTables []byte
	err := pool.QueryRow(ctx, `
		SELECT id, job_id, target_id, object_key, wrapped_dek, plaintext_bytes,
			ciphertext_bytes, ciphertext_sha256, pg_major_version, tables_json,
			verification_passed, restore_duration_ms, verification_error, pruned_at, created_at
		FROM backup_artifacts
		WHERE id = $1
	`, id).Scan(
		&out.ID, &out.JobID, &out.TargetID, &out.ObjectKey, &out.WrappedDEK, &out.PlaintextBytes,
		&out.CiphertextBytes, &out.CiphertextSHA256, &out.PGMajorVersion, &rawTables,
		&out.VerificationPassed, &out.RestoreDurationMs, &out.VerificationError, &out.PrunedAt, &out.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("db: get artifact %d: %w", id, err)
	}
	if err := json.Unmarshal(rawTables, &out.Tables); err != nil {
		return nil, fmt.Errorf("db: unmarshal tables_json: %w", err)
	}
	return &out, nil
}

// GetArtifactByJobID fetches the backup artifact produced by a specific job.
func GetArtifactByJobID(ctx context.Context, pool *pgxpool.Pool, jobID int64) (*BackupArtifact, error) {
	var out BackupArtifact
	var rawTables []byte
	err := pool.QueryRow(ctx, `
		SELECT id, job_id, target_id, object_key, wrapped_dek, plaintext_bytes,
			ciphertext_bytes, ciphertext_sha256, pg_major_version, tables_json,
			verification_passed, restore_duration_ms, verification_error, pruned_at, created_at
		FROM backup_artifacts
		WHERE job_id = $1
	`, jobID).Scan(
		&out.ID, &out.JobID, &out.TargetID, &out.ObjectKey, &out.WrappedDEK, &out.PlaintextBytes,
		&out.CiphertextBytes, &out.CiphertextSHA256, &out.PGMajorVersion, &rawTables,
		&out.VerificationPassed, &out.RestoreDurationMs, &out.VerificationError, &out.PrunedAt, &out.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("db: get artifact for job %d: %w", jobID, err)
	}
	if err := json.Unmarshal(rawTables, &out.Tables); err != nil {
		return nil, fmt.Errorf("db: unmarshal tables_json: %w", err)
	}
	return &out, nil
}

// CreateAlertChannel inserts a new alert channel row.
func CreateAlertChannel(ctx context.Context, pool *pgxpool.Pool, ch AlertChannel) (*AlertChannel, error) {
	var out AlertChannel
	err := pool.QueryRow(ctx, `
		INSERT INTO alert_channels (
			target_id, channel_type, bot_token, chat_id,
			notify_on_failure, notify_on_success, enabled
		) VALUES ($1,$2,$3,$4,$5,$6,$7)
		RETURNING id, target_id, channel_type, bot_token, chat_id,
			notify_on_failure, notify_on_success, enabled, created_at, updated_at
	`,
		ch.TargetID, ch.ChannelType, ch.BotToken, ch.ChatID,
		ch.NotifyOnFailure, ch.NotifyOnSuccess, ch.Enabled,
	).Scan(
		&out.ID, &out.TargetID, &out.ChannelType, &out.BotToken, &out.ChatID,
		&out.NotifyOnFailure, &out.NotifyOnSuccess, &out.Enabled, &out.CreatedAt, &out.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("db: create alert channel: %w", err)
	}
	return &out, nil
}

// ListActiveAlertChannels returns all enabled alert channels that apply globally or to targetID.
func ListActiveAlertChannels(ctx context.Context, pool *pgxpool.Pool, targetID int64) ([]AlertChannel, error) {
	rows, err := pool.Query(ctx, `
		SELECT id, target_id, channel_type, bot_token, chat_id,
			notify_on_failure, notify_on_success, enabled, created_at, updated_at
		FROM alert_channels
		WHERE enabled = TRUE
		  AND (target_id IS NULL OR target_id = $1)
		ORDER BY id ASC
	`, targetID)
	if err != nil {
		return nil, fmt.Errorf("db: list active alert channels: %w", err)
	}
	defer rows.Close()

	var channels []AlertChannel
	for rows.Next() {
		var ch AlertChannel
		if err := rows.Scan(
			&ch.ID, &ch.TargetID, &ch.ChannelType, &ch.BotToken, &ch.ChatID,
			&ch.NotifyOnFailure, &ch.NotifyOnSuccess, &ch.Enabled, &ch.CreatedAt, &ch.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("db: scan alert channel: %w", err)
		}
		channels = append(channels, ch)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db: iterate alert channels: %w", err)
	}
	return channels, nil
}

// ListArtifacts returns backup artifacts optionally filtered by targetID, ordered newest first.
func ListArtifacts(ctx context.Context, pool *pgxpool.Pool, targetID *int64, limit int) ([]BackupArtifact, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	var (
		rows pgx.Rows
		err  error
	)
	if targetID != nil {
		rows, err = pool.Query(ctx, `
			SELECT id, job_id, target_id, object_key, wrapped_dek, plaintext_bytes,
				ciphertext_bytes, ciphertext_sha256, pg_major_version, tables_json,
				verification_passed, restore_duration_ms, verification_error, pruned_at, created_at
			FROM backup_artifacts
			WHERE target_id = $1
			ORDER BY created_at DESC, id DESC
			LIMIT $2
		`, *targetID, limit)
	} else {
		rows, err = pool.Query(ctx, `
			SELECT id, job_id, target_id, object_key, wrapped_dek, plaintext_bytes,
				ciphertext_bytes, ciphertext_sha256, pg_major_version, tables_json,
				verification_passed, restore_duration_ms, verification_error, pruned_at, created_at
			FROM backup_artifacts
			ORDER BY created_at DESC, id DESC
			LIMIT $1
		`, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("db: list artifacts: %w", err)
	}
	defer rows.Close()

	artifacts := make([]BackupArtifact, 0)
	for rows.Next() {
		var out BackupArtifact
		var rawTables []byte
		if err := rows.Scan(
			&out.ID, &out.JobID, &out.TargetID, &out.ObjectKey, &out.WrappedDEK, &out.PlaintextBytes,
			&out.CiphertextBytes, &out.CiphertextSHA256, &out.PGMajorVersion, &rawTables,
			&out.VerificationPassed, &out.RestoreDurationMs, &out.VerificationError, &out.PrunedAt, &out.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("db: scan artifact: %w", err)
		}
		if err := json.Unmarshal(rawTables, &out.Tables); err != nil {
			return nil, fmt.Errorf("db: unmarshal artifact tables_json: %w", err)
		}
		artifacts = append(artifacts, out)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db: iterate artifacts: %w", err)
	}
	return artifacts, nil
}

// ListAllAlertChannels returns all configured alert channels ordered by ID.
func ListAllAlertChannels(ctx context.Context, pool *pgxpool.Pool) ([]AlertChannel, error) {
	rows, err := pool.Query(ctx, `
		SELECT id, target_id, channel_type, bot_token, chat_id,
			notify_on_failure, notify_on_success, enabled, created_at, updated_at
		FROM alert_channels
		ORDER BY id ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("db: list alert channels: %w", err)
	}
	defer rows.Close()

	channels := make([]AlertChannel, 0)
	for rows.Next() {
		var ch AlertChannel
		if err := rows.Scan(
			&ch.ID, &ch.TargetID, &ch.ChannelType, &ch.BotToken, &ch.ChatID,
			&ch.NotifyOnFailure, &ch.NotifyOnSuccess, &ch.Enabled, &ch.CreatedAt, &ch.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("db: scan alert channel: %w", err)
		}
		channels = append(channels, ch)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db: iterate alert channels: %w", err)
	}
	return channels, nil
}

// UpsertTelegramAlertChannel creates or updates the Telegram alert channel for targetID (or global when nil).
// If updating an existing channel and ch.BotToken is empty, the existing bot_token is preserved.
func UpsertTelegramAlertChannel(ctx context.Context, pool *pgxpool.Pool, ch AlertChannel) (*AlertChannel, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("db: begin upsert alert tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var existingID int64
	var existingToken string
	if ch.TargetID == nil {
		err = tx.QueryRow(ctx, `
			SELECT id, bot_token FROM alert_channels
			WHERE channel_type = 'telegram' AND target_id IS NULL
			ORDER BY id ASC LIMIT 1
			FOR UPDATE
		`).Scan(&existingID, &existingToken)
	} else {
		err = tx.QueryRow(ctx, `
			SELECT id, bot_token FROM alert_channels
			WHERE channel_type = 'telegram' AND target_id = $1
			ORDER BY id ASC LIMIT 1
			FOR UPDATE
		`, *ch.TargetID).Scan(&existingID, &existingToken)
	}

	var out AlertChannel
	if errors.Is(err, pgx.ErrNoRows) {
		if strings.TrimSpace(ch.BotToken) == "" {
			return nil, errors.New("db: bot_token is required when creating telegram alert channel")
		}
		err = tx.QueryRow(ctx, `
			INSERT INTO alert_channels (
				target_id, channel_type, bot_token, chat_id,
				notify_on_failure, notify_on_success, enabled
			) VALUES ($1, 'telegram', $2, $3, $4, $5, $6)
			RETURNING id, target_id, channel_type, bot_token, chat_id,
				notify_on_failure, notify_on_success, enabled, created_at, updated_at
		`, ch.TargetID, ch.BotToken, ch.ChatID, ch.NotifyOnFailure, ch.NotifyOnSuccess, ch.Enabled).Scan(
			&out.ID, &out.TargetID, &out.ChannelType, &out.BotToken, &out.ChatID,
			&out.NotifyOnFailure, &out.NotifyOnSuccess, &out.Enabled, &out.CreatedAt, &out.UpdatedAt,
		)
	} else if err == nil {
		tokenToStore := ch.BotToken
		if strings.TrimSpace(tokenToStore) == "" {
			tokenToStore = existingToken
		}
		err = tx.QueryRow(ctx, `
			UPDATE alert_channels
			SET bot_token = $2,
				chat_id = $3,
				notify_on_failure = $4,
				notify_on_success = $5,
				enabled = $6,
				updated_at = NOW()
			WHERE id = $1
			RETURNING id, target_id, channel_type, bot_token, chat_id,
				notify_on_failure, notify_on_success, enabled, created_at, updated_at
		`, existingID, tokenToStore, ch.ChatID, ch.NotifyOnFailure, ch.NotifyOnSuccess, ch.Enabled).Scan(
			&out.ID, &out.TargetID, &out.ChannelType, &out.BotToken, &out.ChatID,
			&out.NotifyOnFailure, &out.NotifyOnSuccess, &out.Enabled, &out.CreatedAt, &out.UpdatedAt,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("db: upsert telegram alert channel: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("db: commit upsert alert tx: %w", err)
	}
	return &out, nil
}
